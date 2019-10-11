/* packet-dash.c
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
 * Converted from bitcoin -> dash 2017
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
#include <stdio.h>

#include <epan/packet.h>
#include <epan/exceptions.h>
#include <epan/prefs.h>
#include <epan/expert.h>

#include <epan/dissectors/packet-tcp.h>

#define DASH_MAIN_MAGIC_NUMBER       0xBD6B0CBF
#define DASH_REGTEST_MAGIC_NUMBER    0xDCB7C1FC
#define DASH_TESTNET3_MAGIC_NUMBER   0xFFCAE2CE
#define DASH_DEVNET_MAGIC_NUMBER     0xCEFFCAE2

static const value_string inv_types[] =
{
  // // Defined in https://github.com/dashpay/dash/blob/master/src/protocol.h
  { 0, "ERROR" },
  { 1, "MSG_TX" },
  { 2, "MSG_BLOCK" },
  { 3, "MSG_FILTERED_BLOCK" },
  { 4, "MSG_TXLOCK_REQUEST" },
  { 5, "MSG_TXLOCK_VOTE" },
  { 6, "MSG_SPORK" },
  { 7, "MSG_MASTERNODE_PAYMENT_VOTE" },
  { 8, "MSG_MASTERNODE_PAYMENT_BLOCK (prev. MSG_MASTERNODE_SCANNING_ERROR)" },
  { 9, "MSG_BUDGET_VOTE (DEPRECATED)" },
  { 10, "MSG_BUDGET_PROPOSAL (DEPRECATED)" },
  { 11, "MSG_BUDGET_FINALIZED (DEPRECATED)" },
  { 12, "MSG_BUDGET_FINALIZED_VOTE (DEPRECATED)" },
  { 13, "MSG_MASTERNODE_QUORUM" },
  { 14, "MSG_MASTERNODE_ANNOUNCE" },
  { 15, "MSG_MASTERNODE_PING" },
  { 16, "MSG_DSTX" },
  { 17, "MSG_GOVERNANCE_OBJECT" },
  { 18, "MSG_GOVERNANCE_OBJECT_VOTE" },
  { 19, "MSG_MASTERNODE_VERIFY" },
  { 20, "MSG_CMPCT_BLOCK" },
  { 21, "MSG_QUORUM_FINAL_COMMITMENT" },
  { 23, "MSG_QUORUM_CONTRIB" },
  { 24, "MSG_QUORUM_COMPLAINT" },
  { 25, "MSG_QUORUM_JUSTIFICATION" },
  { 26, "MSG_QUORUM_PREMATURE_COMMITMENT" },
  { 27, "MSG_QUORUM_DEBUG_STATUS (DEPRECATED)" },
  { 28, "MSG_QUORUM_RECOVERED_SIG" },
  { 29, "MSG_CLSIG" },
  { 30, "MSG_ISLOCK" },
  { 0, NULL }
};

static const value_string reject_ccode[] =
{
  // Defined in https://github.com/dashpay/dash/blob/master/src/consensus/validation.h
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
  // Defined in https://github.com/dashpay/dash/blob/master/src/bloom.h
  // enum bloomflags
  { 0, "BLOOM_UPDATE_NONE" },
  { 1, "BLOOM_UPDATE_ALL" },
  { 2, "BLOOM_UPDATE_P2PUBKEY_ONLY" },
  { 3, "BLOOM_UPDATE_MASK" },
  { 0, NULL }
};

static const value_string vote_outcome[] =
{
  // Defined in src/governance-vote.cpp - vote_outcome_enum_t
  // https://github.com/dashpay/dash/blob/master/src/governance-vote.h

  { 0x01, "VOTE_OUTCOME_NONE" },
  { 0x02, "VOTE_OUTCOME_YES" },
  { 0x03, "VOTE_OUTCOME_NO" },
  { 0x04, "VOTE_OUTCOME_ABSTAIN" },
};

static const value_string vote_signal[] =
{
  // Defined in src/governance-vote.cpp - vote_signal_enum_t
  // https://github.com/dashpay/dash/blob/master/src/governance-vote.h

  { 0x00, "VOTE_SIGNAL_NONE" }, //   -- fund this object for it's stated amount
  { 0x01, "VOTE_SIGNAL_FUNDING" }, //   -- this object checks out in sentinel engine
  { 0x02, "VOTE_SIGNAL_VALID" }, //   -- this object should be deleted from memory entirely
  { 0x03, "VOTE_SIGNAL_DELETE" },
  { 0x04, "VOTE_SIGNAL_ENDORSED" }, //   -- officially endorsed by the network somehow (delegation)
  { 0x05, "VOTE_SIGNAL_NOOP1" }, // FOR FURTHER EXPANSION
  { 0x06, "VOTE_SIGNAL_NOOP2" },
  { 0x07, "VOTE_SIGNAL_NOOP3" },
  { 0x08, "VOTE_SIGNAL_NOOP4" },
  { 0x09, "VOTE_SIGNAL_NOOP5" },
  { 0x10, "VOTE_SIGNAL_NOOP6" },
  { 0x11, "VOTE_SIGNAL_NOOP7" },
  { 0x12, "VOTE_SIGNAL_NOOP8" },
  { 0x13, "VOTE_SIGNAL_NOOP9" },
  { 0x14, "VOTE_SIGNAL_NOOP10" },
  { 0x15, "VOTE_SIGNAL_NOOP11" },

  { 0x16, "VOTE_SIGNAL_CUSTOM1" }, // SENTINEL CUSTOM ACTIONS
  { 0x17, "VOTE_SIGNAL_CUSTOM2" }, //        16-35
  { 0x18, "VOTE_SIGNAL_CUSTOM3" },
  { 0x19, "VOTE_SIGNAL_CUSTOM4" },
  { 0x20, "VOTE_SIGNAL_CUSTOM5" },
  { 0x21, "VOTE_SIGNAL_CUSTOM6" },
  { 0x22, "VOTE_SIGNAL_CUSTOM7" },
  { 0x23, "VOTE_SIGNAL_CUSTOM8" },
  { 0x24, "VOTE_SIGNAL_CUSTOM9" },
  { 0x25, "VOTE_SIGNAL_CUSTOM10" },
  { 0x26, "VOTE_SIGNAL_CUSTOM11" },
  { 0x27, "VOTE_SIGNAL_CUSTOM12" },
  { 0x28, "VOTE_SIGNAL_CUSTOM13" },
  { 0x29, "VOTE_SIGNAL_CUSTOM14" },
  { 0x30, "VOTE_SIGNAL_CUSTOM15" },
  { 0x31, "VOTE_SIGNAL_CUSTOM16" },
  { 0x32, "VOTE_SIGNAL_CUSTOM17" },
  { 0x33, "VOTE_SIGNAL_CUSTOM18" },
  { 0x34, "VOTE_SIGNAL_CUSTOM19" },
  { 0x35, "VOTE_SIGNAL_CUSTOM20" },
};

static const value_string private_send_denomination[] =
{
  // Defined in src/darksend.cpp - InitDenominations()
  // https://github.com/dashpay/dash/blob/master/src/darksend.cpp
  { 0x01, "10 DASH" },
  { 0x02, "1 DASH" },
  { 0x04, "0.1 DASH" },
  { 0x08, "0.01 DASH" },
  { 0x10, "0.001 DASH" },
};

static const value_string pool_message[] =
{
  // Defined in src/privatesend.h
  // https://github.com/dashpay/dash/blob/master/src/privatesend.h
  { 0, "ERR_ALREADY_HAVE"},
  { 1, "ERR_DENOM" },
  { 2, "ERR_ENTRIES_FULL" },
  { 3, "ERR_EXISTING_TX" },
  { 4, "ERR_FEES" },
  { 5, "ERR_INVALID_COLLATERAL" },
  { 6, "ERR_INVALID_INPUT" },
  { 7, "ERR_INVALID_SCRIPT" },
  { 8, "ERR_INVALID_TX" },
  { 9, "ERR_MAXIMUM" },
  { 10, "ERR_MN_LIST" },
  { 11, "ERR_MODE" },
  { 12, "ERR_NON_STANDARD_PUBKEY" },
  { 13, "ERR_NOT_A_MN" }, // Not used
  { 14, "ERR_QUEUE_FULL" },
  { 15, "ERR_RECENT" },
  { 16, "ERR_SESSION" },
  { 17, "ERR_MISSING_TX" },
  { 18, "ERR_VERSION" },
  { 19, "MSG_NOERR" },
  { 20, "MSG_SUCCESS" },
  { 21, "MSG_ENTRIES_ADDED" },
};

static const value_string pool_state[] =
{
  // Defined in src/darksend.h
  // https://github.com/dashpay/dash/blob/master/src/darksend.h
  { 0, "POOL_STATE_IDLE"},
  { 1, "POOL_STATE_QUEUE" },
  { 2, "POOL_STATE_ACCEPTING_ENTRIES" },
  { 3, "POOL_STATE_SIGNING" },
  { 4, "POOL_STATE_ERROR" },
  { 5, "POOL_STATE_SUCCESS" },
};

static const value_string pool_status_update[] =
{
  // Defined in src/darksend.h
  // https://github.com/dashpay/dash/blob/master/src/darksend.h
  { 0, "STATUS_REJECTED"},
  { 1, "STATUS_ACCEPTED" },
};

static const value_string spork_description[] =
{
  // Defined in src/spork.h
  // https://github.com/dashpay/dash/blob/master/src/spork.h
  { 10001, "SPORK_2_INSTANTSEND_ENABLED" },
  { 10002, "SPORK_3_INSTANTSEND_BLOCK_FILTERING" },
  { 10004, "SPORK_5_INSTANTSEND_MAX_VALUE" },
  { 10005, "SPORK_6_NEW_SIGS" },
  { 10007, "DEPRECATED_SPORK_8_MASTERNODE_PAYMENT_ENFORCEMENT" },
  { 10008, "SPORK_9_SUPERBLOCKS_ENABLED" },
  { 10009, "DEPRECATED_SPORK_10_MASTERNODE_PAY_UPDATED_NODES" },
  { 10011, "SPORK_12_RECONSIDER_BLOCKS" },
  { 10012, "DEPRECATED_SPORK_13_OLD_SUPERBLOCK_FLAG" },
  { 10013, "DEPRECATED_SPORK_14_REQUIRE_SENTINEL_FLAG" },
  { 10014, "SPORK_15_DETERMINISTIC_MNS_ENABLED" },
  { 10015, "SPORK_16_INSTANTSEND_AUTOLOCKS" },
  { 10016, "SPORK_17_QUORUM_DKG_ENABLED" },
  { 10017, "DEPRECATED_SPORK_18_QUORUM_DEBUG_ENABLED" },
  { 10018, "SPORK_19_CHAINLOCKS_ENABLED" },
  { 10019, "SPORK_20_INSTANTSEND_LLMQ_BASED" },
};

static const value_string masternode_sync_item_id[] =
{
  // Defined in src/masternodesync.h
  // https://github.com/dashpay/dash/blob/master/src/masternode-sync.h
  { -1, "MASTERNODE_SYNC_FAILED" },
  { 0, "MASTERNODE_SYNC_INITIAL" },
  { 1, "MASTERNODE_SYNC_SPORKS" },
  { 2, "MASTERNODE_SYNC_LIST (DEPRECATED)" },
  { 3, "MASTERNODE_SYNC_MNW (DEPRECATED)" },
  { 4, "MASTERNODE_SYNC_GOVERNANCE" },
  { 10, "MASTERNODE_SYNC_GOVOBJ" },
  { 11, "MASTERNODE_SYNC_GOVOBJ_VOTE" },
  { 999, "MASTERNODE_SYNC_FINISHED" },

  // Not sure if these belong here
  { 6, "MASTERNODE_SYNC_TICK_SECONDS???" },
  { 30, "MASTERNODE_SYNC_TIMEOUT_SECONDS???" },
};

static const value_string governance_object[] =
{
  // Defined in src/governance-object.h
  // https://github.com/dashpay/dash/blob/master/src/governance-object.h
  { 0, "GOVERNANCE_OBJECT_UNKNOWN" },
  { 1, "GOVERNANCE_OBJECT_PROPOSAL" },
  { 2, "GOVERNANCE_OBJECT_TRIGGER" },
  { 3, "GOVERNANCE_OBJECT_WATCHDOG" },

};

static const value_string pubkey_type[] =
{
  // Defined in src/pubkey.h
  // https://github.com/dashpay/dash/blob/master/src/pubkey.h
  { 2, "COMPRESSED - Even" },
  { 3, "COMPRESSED - Odd" },
  { 4, "UNCOMPRESSED" },
  { 6, "UNCOMPRESSED" },
  { 7, "UNCOMPRESSED" },
};

static const value_string special_tx_type[] =
{
  { 0, "Classical Transaction (No extra DIP-2 payload)" },
  { 1, "Provider Registration (ProRegTx)" },
  { 2, "Provider Update - Service (ProUpServTx)" },
  { 3, "Provider Update - Registrar (ProUpRegTx)" },
  { 4, "Provider Update - Key Revocation (ProUpRevTx)" },
  { 5, "Coinbase (CbTx)" },
  { 6, "Quorum Commitment (QcTx)" },
  { 7, "RESERVED" },
  { 8, "Subscription - Registration (SubTxRegister)" },
  { 9, "Subscription - Topup (SubTxTopup)" },
  { 10, "Subscription - Key Change (SubTxResetKey)" },
  { 11, "Subscription - Account Close (SubTxCloseAccount)" },
};

static const value_string llmq_type[] =
{
  // Defined in src/consensus/params.h
  { 1,   "LLMQ_50_60" },
  { 2,   "LLMQ_400_60" },
  { 3,   "LLMQ_400_85" },
  { 100, "LLMQ_5_60" },
};

/*
 * Minimum dash identification header.
 * - Magic - 4 bytes
 * - Command - 12 bytes
 * - Payload length - 4 bytes
 * - Checksum - 4 bytes
 */
#define DASH_HEADER_LENGTH 4+12+4+4

void proto_register_dash(void);
void proto_reg_handoff_dash(void);

static dissector_handle_t dash_handle;

static dissector_table_t dash_command_table;

static header_field_info *hfi_dash = NULL;

#define DASH_HFI_INIT HFI_INIT(proto_dash)

static header_field_info hfi_dash_magic DASH_HFI_INIT =
  { "Packet magic", "dash.magic", FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL };

static header_field_info hfi_dash_command DASH_HFI_INIT =
  { "Command name", "dash.command", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL };

static header_field_info hfi_dash_length DASH_HFI_INIT =
  { "Payload Length", "dash.length", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL };

static header_field_info hfi_dash_checksum DASH_HFI_INIT =
  { "Payload checksum", "dash.checksum", FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL };

// Generic (re-usable) fields

static header_field_info hfi_msg_field_size DASH_HFI_INIT =
  { "Field Size", "dash.generic.fieldsize", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL };

static header_field_info hfi_msg_pubkey_type DASH_HFI_INIT =
  { "Public Key Type", "dash.generic.pubkeytype", FT_UINT8, BASE_DEC, VALS(pubkey_type), 0x0, NULL, HFILL };

  static header_field_info hfi_msg_pubkey_hash DASH_HFI_INIT =
    { "Public Key Hash", "dash.generic.pubkeyhash", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL };

/* CPubkey structure */
static header_field_info hfi_dash_cpubkey DASH_HFI_INIT =
  { "Public Key", "dash.cpubkey", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL };

/* COutPoint structure */
static header_field_info hfi_dash_coutpoint DASH_HFI_INIT =
  { "Outpoint", "dash.coutpoint", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL };

/* version message */
static header_field_info hfi_dash_msg_version DASH_HFI_INIT =
  { "Version message", "dash.version", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL };

static header_field_info hfi_msg_version_version DASH_HFI_INIT =
  { "Protocol version", "dash.version.version", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL };

static header_field_info hfi_msg_version_services DASH_HFI_INIT =
  { "Node services", "dash.version.services", FT_UINT64, BASE_HEX, NULL, 0x0, NULL, HFILL };

static header_field_info hfi_msg_version_timestamp DASH_HFI_INIT =
  { "Node timestamp", "dash.version.timestamp", FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL, NULL, 0x0, NULL, HFILL };

static header_field_info hfi_msg_version_addr_me DASH_HFI_INIT =
  { "Address of emmitting node", "dash.version.addr_me", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL };

static header_field_info hfi_msg_version_addr_you DASH_HFI_INIT =
  { "Address as receiving node", "dash.version.addr_you", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL };

static header_field_info hfi_msg_version_nonce DASH_HFI_INIT =
  { "Random nonce", "dash.version.nonce", FT_UINT64, BASE_HEX, NULL, 0x0, NULL, HFILL };

static header_field_info hfi_msg_version_user_agent DASH_HFI_INIT =
  { "User agent", "dash.version.user_agent", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL };

static header_field_info hfi_msg_version_start_height DASH_HFI_INIT =
  { "Block start height", "dash.version.start_height", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL };

static header_field_info hfi_msg_version_relay DASH_HFI_INIT =
  { "Relay flag", "dash.version.relay", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL };

static header_field_info hfi_msg_version_mn_challenge DASH_HFI_INIT =
  { "Masternode Auth Challenge", "dash.version.mnchallenge", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL };

/* addr message */
static header_field_info hfi_msg_addr_count8 DASH_HFI_INIT =
  { "Count", "dash.addr.count", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL };

static header_field_info hfi_msg_addr_count16 DASH_HFI_INIT =
  { "Count", "dash.addr.count", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL };

static header_field_info hfi_msg_addr_count32 DASH_HFI_INIT =
  { "Count", "dash.addr.count", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL };

static header_field_info hfi_msg_addr_count64 DASH_HFI_INIT =
  { "Count", "dash.addr.count64", FT_UINT64, BASE_DEC, NULL, 0x0, NULL, HFILL };

static header_field_info hfi_dash_msg_addr DASH_HFI_INIT =
  { "Address message", "dash.addr", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL };

static header_field_info hfi_msg_addr_address DASH_HFI_INIT =
  { "Address", "dash.addr.address", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL };

static header_field_info hfi_msg_addr_timestamp DASH_HFI_INIT =
  { "Address timestamp", "dash.addr.timestamp", FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL, NULL, 0x0, NULL, HFILL };

/* inv message */
static header_field_info hfi_msg_inv_count8 DASH_HFI_INIT =
  { "Count", "dash.inv.count", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL };

static header_field_info hfi_msg_inv_count16 DASH_HFI_INIT =
  { "Count", "dash.inv.count", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL };

static header_field_info hfi_msg_inv_count32 DASH_HFI_INIT =
  { "Count", "dash.inv.count", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL };

static header_field_info hfi_msg_inv_count64 DASH_HFI_INIT =
  { "Count", "dash.inv.count64", FT_UINT64, BASE_DEC, NULL, 0x0, NULL, HFILL };

static header_field_info hfi_dash_msg_inv DASH_HFI_INIT =
  { "Inventory message", "dash.inv", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL };

static header_field_info hfi_msg_inv_type DASH_HFI_INIT =
  { "Type", "dash.inv.type", FT_UINT32, BASE_DEC, VALS(inv_types), 0x0, NULL, HFILL };

static header_field_info hfi_msg_inv_hash DASH_HFI_INIT =
  { "Data hash", "dash.inv.hash", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL };

/* getdata message */
static header_field_info hfi_dash_msg_getdata DASH_HFI_INIT =
  { "Getdata message", "dash.getdata", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL };

static header_field_info hfi_msg_getdata_count8 DASH_HFI_INIT =
  { "Count", "dash.getdata.count", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL };

static header_field_info hfi_msg_getdata_count16 DASH_HFI_INIT =
  { "Count", "dash.getdata.count", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL };

static header_field_info hfi_msg_getdata_count32 DASH_HFI_INIT =
  { "Count", "dash.getdata.count", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL };

static header_field_info hfi_msg_getdata_count64 DASH_HFI_INIT =
  { "Count", "dash.getdata.count64", FT_UINT64, BASE_DEC, NULL, 0x0, NULL, HFILL };

static header_field_info hfi_msg_getdata_type DASH_HFI_INIT =
  { "Type", "dash.getdata.type", FT_UINT32, BASE_DEC, VALS(inv_types), 0x0, NULL, HFILL };

static header_field_info hfi_msg_getdata_hash DASH_HFI_INIT =
  { "Data hash", "dash.getdata.hash", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL };

/* notfound message */
static header_field_info hfi_msg_notfound_count8 DASH_HFI_INIT =
  { "Count", "dash.notfound.count", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL };

static header_field_info hfi_msg_notfound_count16 DASH_HFI_INIT =
  { "Count", "dash.notfound.count", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL };

static header_field_info hfi_msg_notfound_count32 DASH_HFI_INIT =
  { "Count", "dash.notfound.count", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL };

static header_field_info hfi_msg_notfound_count64 DASH_HFI_INIT =
  { "Count", "dash.notfound.count64", FT_UINT64, BASE_DEC, NULL, 0x0, NULL, HFILL };

static header_field_info hfi_dash_msg_notfound DASH_HFI_INIT =
  { "Getdata message", "dash.notfound", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL };

static header_field_info hfi_msg_notfound_type DASH_HFI_INIT =
  { "Type", "dash.notfound.type", FT_UINT32, BASE_DEC, VALS(inv_types), 0x0, NULL, HFILL };

static header_field_info hfi_msg_notfound_hash DASH_HFI_INIT =
  { "Data hash", "dash.notfound.hash", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL };

/* getblocks message */
static header_field_info hfi_msg_getblocks_count8 DASH_HFI_INIT =
  { "Count", "dash.getblocks.count", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL };

static header_field_info hfi_msg_getblocks_count16 DASH_HFI_INIT =
  { "Count", "dash.getblocks.count", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL };

static header_field_info hfi_msg_getblocks_count32 DASH_HFI_INIT =
  { "Count", "dash.getblocks.count", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL };

static header_field_info hfi_msg_getblocks_count64 DASH_HFI_INIT =
  { "Count", "dash.getblocks.count64", FT_UINT64, BASE_DEC, NULL, 0x0, NULL, HFILL };

static header_field_info hfi_dash_msg_getblocks DASH_HFI_INIT =
  { "Getdata message", "dash.getblocks", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL };

static header_field_info hfi_msg_getblocks_start DASH_HFI_INIT =
  { "Starting hash", "dash.getblocks.hash_start", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL };

static header_field_info hfi_msg_getblocks_stop DASH_HFI_INIT =
  { "Stopping hash", "dash.getblocks.hash_stop", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL };

/* getheaders message */
static header_field_info hfi_msg_getheaders_count8 DASH_HFI_INIT =
  { "Count", "dash.getheaders.count", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL };

static header_field_info hfi_msg_getheaders_count16 DASH_HFI_INIT =
  { "Count", "dash.getheaders.count", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL };

static header_field_info hfi_msg_getheaders_count32 DASH_HFI_INIT =
  { "Count", "dash.getheaders.count", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL };

static header_field_info hfi_msg_getheaders_count64 DASH_HFI_INIT =
  { "Count", "dash.getheaders.count64", FT_UINT64, BASE_DEC, NULL, 0x0, NULL, HFILL };

#if 0
static header_field_info hfi_msg_getheaders_version DASH_HFI_INIT =
  { "Protocol version", "dash.headers.version", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL };
#endif

static header_field_info hfi_dash_msg_getheaders DASH_HFI_INIT =
  { "Getheaders message", "dash.getheaders", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL };

static header_field_info hfi_msg_getheaders_start DASH_HFI_INIT =
  { "Starting hash", "dash.getheaders.hash_start", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL };

static header_field_info hfi_msg_getheaders_stop DASH_HFI_INIT =
  { "Stopping hash", "dash.getheaders.hash_stop", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL };

/* tx message */
static header_field_info hfi_msg_tx_in_count8 DASH_HFI_INIT =
  { "Input Count", "dash.tx.input_count", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL };

static header_field_info hfi_msg_tx_in_count16 DASH_HFI_INIT =
  { "Input Count", "dash.tx.input_count", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL };

static header_field_info hfi_msg_tx_in_count32 DASH_HFI_INIT =
  { "Input Count", "dash.tx.input_count", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL };

static header_field_info hfi_msg_tx_in_count64 DASH_HFI_INIT =
  { "Input Count", "dash.tx.input_count64", FT_UINT64, BASE_DEC, NULL, 0x0, NULL, HFILL };

static header_field_info hfi_dash_msg_tx DASH_HFI_INIT =
  { "Tx message", "dash.tx", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL };

static header_field_info hfi_msg_tx_version DASH_HFI_INIT =
  { "Transaction version", "dash.tx.version", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL };

  static header_field_info hfi_msg_tx_type DASH_HFI_INIT =
    { "Transaction type", "dash.tx.type", FT_UINT16, BASE_DEC, VALS(special_tx_type), 0x0, NULL, HFILL };

static header_field_info hfi_msg_tx_in_script8 DASH_HFI_INIT =
  { "Script Length", "dash.tx.in.script_length", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL };

static header_field_info hfi_msg_tx_in_script16 DASH_HFI_INIT =
  { "Script Length", "dash.tx.in.script_length", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL };

static header_field_info hfi_msg_tx_in_script32 DASH_HFI_INIT =
  { "Script Length", "dash.tx.in.script_length", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL };

static header_field_info hfi_msg_tx_in_script64 DASH_HFI_INIT =
  { "Script Length", "dash.tx.in.script_length64", FT_UINT64, BASE_DEC, NULL, 0x0, NULL, HFILL };

static header_field_info hfi_msg_tx_in DASH_HFI_INIT =
  { "Transaction input", "dash.tx.in", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL };

static header_field_info hfi_msg_tx_in_prev_output DASH_HFI_INIT =
  { "Previous output (UTXO)", "dash.tx.in.prev_output", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL };

static header_field_info hfi_msg_tx_in_prev_outp_hash DASH_HFI_INIT =
  { "Hash", "dash.tx.in.prev_output.hash", FT_BYTES, BASE_NONE, NULL, 0x0, "Hash of the previous output", HFILL };

// Using to display flipped endian
static header_field_info hfi_msg_tx_in_prev_outp_hash_reversed DASH_HFI_INIT =
  { "Hash (reverse endian)", "dash.tx.in.prev_output.hash2", FT_STRING, BASE_NONE, NULL, 0x0, "Hash of previous output (reversed endianness)", HFILL };

static header_field_info hfi_msg_tx_in_prev_outp_index DASH_HFI_INIT =
  { "Index", "dash.tx.in.prev_output.index", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL };

static header_field_info hfi_msg_tx_in_sig_script DASH_HFI_INIT =
  { "Signature script", "dash.tx.in.sig_script", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL };

static header_field_info hfi_msg_tx_in_seq DASH_HFI_INIT =
  { "Sequence", "dash.tx.in.seq", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL };

static header_field_info hfi_msg_tx_out_count8 DASH_HFI_INIT =
  { "Output Count", "dash.tx.output_count", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL };

static header_field_info hfi_msg_tx_out_count16 DASH_HFI_INIT =
  { "Output Count", "dash.tx.output_count", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL };

static header_field_info hfi_msg_tx_out_count32 DASH_HFI_INIT =
  { "Output Count", "dash.tx.output_count", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL };

static header_field_info hfi_msg_tx_out_count64 DASH_HFI_INIT =
  { "Output Count", "dash.tx.output_count64", FT_UINT64, BASE_DEC, NULL, 0x0, NULL, HFILL };

static header_field_info hfi_msg_tx_out DASH_HFI_INIT =
  { "Transaction output", "dash.tx.out", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL };

static header_field_info hfi_msg_tx_out_value DASH_HFI_INIT =
  { "Value", "dash.tx.out.value", FT_UINT64, BASE_DEC, NULL, 0x0, NULL, HFILL };

static header_field_info hfi_msg_tx_out_script8 DASH_HFI_INIT =
  { "Script Length", "dash.tx.out.script_length", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL };

static header_field_info hfi_msg_tx_out_script16 DASH_HFI_INIT =
  { "Script Length", "dash.tx.out.script_length", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL };

static header_field_info hfi_msg_tx_out_script32 DASH_HFI_INIT =
  { "Script Length", "dash.tx.out.script_length", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL };

static header_field_info hfi_msg_tx_out_script64 DASH_HFI_INIT =
  { "Script Length", "dash.tx.out.script_length64", FT_UINT64, BASE_DEC, NULL, 0x0, NULL, HFILL };

static header_field_info hfi_msg_tx_out_script DASH_HFI_INIT =
  { "Script", "dash.tx.out.script", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL };

static header_field_info hfi_msg_tx_lock_time DASH_HFI_INIT =
  { "Block lock time or block ID", "dash.tx.lock_time", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL };

static header_field_info hfi_msg_tx_extra_payload_size8 DASH_HFI_INIT =
  { "Extra Payload Size", "dash.tx.extra_payload_size", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL };

static header_field_info hfi_msg_tx_extra_payload_size16 DASH_HFI_INIT =
  { "Extra Payload Size", "dash.tx.extra_payload_size", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL };

static header_field_info hfi_msg_tx_extra_payload_size32 DASH_HFI_INIT =
  { "Extra Payload Size", "dash.tx.extra_payload_size", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL };

static header_field_info hfi_msg_tx_extra_payload_size64 DASH_HFI_INIT =
  { "Extra Payload Size", "dash.tx.extra_payload_size", FT_UINT64, BASE_DEC, NULL, 0x0, NULL, HFILL };

static header_field_info hfi_msg_tx_extra_payload DASH_HFI_INIT =
  { "Extra Payload", "dash.tx.extra_payload", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL };

/* tx.proregtx */
static header_field_info hfi_msg_tx_extra_proregtx DASH_HFI_INIT =
  { "ProRegTx Payload", "dash.tx.proregtx", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL };
static header_field_info hfi_msg_tx_extra_proregtx_version DASH_HFI_INIT =
  { "Version", "dash.tx.proregtx.version", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL };
static header_field_info hfi_msg_tx_extra_proregtx_type DASH_HFI_INIT =
  { "Type", "dash.tx.proregtx.type", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL };
static header_field_info hfi_msg_tx_extra_proregtx_mode DASH_HFI_INIT =
  { "Mode", "dash.tx.proregtx.mode", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL };
static header_field_info hfi_msg_tx_extra_proregtx_collateral_outpoint DASH_HFI_INIT =
  { "Collateral Outpoints", "dash.tx.proregtx.outpoint", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL };
static header_field_info hfi_msg_tx_extra_proregtx_ipaddr DASH_HFI_INIT =
  { "IP address", "dash.tx.proregtx.ipaddr", FT_IPv6, BASE_NONE, NULL, 0x0, NULL, HFILL };
static header_field_info hfi_msg_tx_extra_proregtx_port DASH_HFI_INIT =
  { "Port", "dash.tx.proregtx.port", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL };
static header_field_info hfi_msg_tx_extra_proregtx_keyid_owner DASH_HFI_INIT =
  { "Owner pubkey hash (ECDSA)", "dash.tx.proregtx.keyidowner", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL };
static header_field_info hfi_msg_tx_extra_proregtx_opr_pubkey DASH_HFI_INIT =
  { "Operator public key (BLS)", "dash.tx.proregtx.pubkeyoperator", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL };
static header_field_info hfi_msg_tx_extra_proregtx_keyid_voting DASH_HFI_INIT =
  { "Voting pubkey hash (ECDSA)", "dash.tx.proregtx.keyidvoting", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL };
static header_field_info hfi_msg_tx_extra_proregtx_opr_reward DASH_HFI_INIT =
  { "Operator reward", "dash.tx.proregtx.operatorreward", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL };
static header_field_info hfi_msg_tx_extra_proregtx_script DASH_HFI_INIT =
  { "Payout script", "dash.tx.proregtx.script", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL };
static header_field_info hfi_msg_tx_extra_proregtx_script_size8 DASH_HFI_INIT =
  { "Size", "dash.tx.proregtx.script.size", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL };
static header_field_info hfi_msg_tx_extra_proregtx_script_size16 DASH_HFI_INIT =
  { "Size", "dash.tx.proregtx.script.size", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL };
static header_field_info hfi_msg_tx_extra_proregtx_script_size32 DASH_HFI_INIT =
  { "Size", "dash.tx.proregtx.script.size", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL };
static header_field_info hfi_msg_tx_extra_proregtx_script_size64 DASH_HFI_INIT =
  { "Size", "dash.tx.proregtx.script.size", FT_UINT64, BASE_DEC, NULL, 0x0, NULL, HFILL };
static header_field_info hfi_msg_tx_extra_proregtx_script_data DASH_HFI_INIT =
  { "Data", "dash.tx.proregtx.script.data", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL };
static header_field_info hfi_msg_tx_extra_proregtx_inputshash DASH_HFI_INIT =
  { "Inputs hash", "dash.tx.proregtx.inputshash", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL };
static header_field_info hfi_msg_tx_extra_proregtx_payloadsig_size8 DASH_HFI_INIT =
  { "Signature Size", "dash.tx.proregtx.payloadsigsize", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL };
static header_field_info hfi_msg_tx_extra_proregtx_payloadsig_size16 DASH_HFI_INIT =
  { "Signature Size", "dash.tx.proregtx.payloadsigsize", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL };
static header_field_info hfi_msg_tx_extra_proregtx_payloadsig_size32 DASH_HFI_INIT =
  { "Signature Size", "dash.tx.proregtx.payloadsigsize", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL };
static header_field_info hfi_msg_tx_extra_proregtx_payloadsig_size64 DASH_HFI_INIT =
  { "Signature Size", "dash.tx.proregtx.payloadsigsize", FT_UINT64, BASE_DEC, NULL, 0x0, NULL, HFILL };
static header_field_info hfi_msg_tx_extra_proregtx_payloadsig DASH_HFI_INIT =
  { "Signature", "dash.tx.proregtx.payloadsig", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL };

/* tx.proupservtx */
static header_field_info hfi_msg_tx_extra_proupservtx DASH_HFI_INIT =
  { "ProUpServTx Payload", "dash.tx.proupservtx", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL };
static header_field_info hfi_msg_tx_extra_proupservtx_version DASH_HFI_INIT =
  { "Version", "dash.tx.proupservtx.version", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL };
static header_field_info hfi_msg_tx_extra_proupservtx_protxhash DASH_HFI_INIT =
  { "ProRegTx Hash", "dash.tx.proupservtx.protxhash", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL };
static header_field_info hfi_msg_tx_extra_proupservtx_ipaddr DASH_HFI_INIT =
  { "IP address", "dash.tx.proupservtx.ipaddr", FT_IPv6, BASE_NONE, NULL, 0x0, NULL, HFILL };
static header_field_info hfi_msg_tx_extra_proupservtx_port DASH_HFI_INIT =
  { "Port", "dash.tx.proupservtx.port", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL };
static header_field_info hfi_msg_tx_extra_proupservtx_script_size8 DASH_HFI_INIT =
  { "Operator Payout script size", "dash.tx.proupservtx.scriptsize", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL };
static header_field_info hfi_msg_tx_extra_proupservtx_script_size16 DASH_HFI_INIT =
  { "Operator Payout script size", "dash.tx.proupservtx.scriptsize", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL };
static header_field_info hfi_msg_tx_extra_proupservtx_script_size32 DASH_HFI_INIT =
  { "Operator Payout script size", "dash.tx.proupservtx.scriptsize", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL };
static header_field_info hfi_msg_tx_extra_proupservtx_script_size64 DASH_HFI_INIT =
  { "Operator Payout script size", "dash.tx.proupservtx.scriptsize", FT_UINT64, BASE_DEC, NULL, 0x0, NULL, HFILL };
static header_field_info hfi_msg_tx_extra_proupservtx_script DASH_HFI_INIT =
  { "Operator Payout script", "dash.tx.proupservtx.script", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL };
static header_field_info hfi_msg_tx_extra_proupservtx_inputshash DASH_HFI_INIT =
  { "Inputs hash", "dash.tx.proupservtx.inputshash", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL };
static header_field_info hfi_msg_tx_extra_proupservtx_payloadsig DASH_HFI_INIT =
  { "Bls Signature", "dash.tx.proupservtx.payloadsig", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL };

/* tx.proupregtx */
static header_field_info hfi_msg_tx_extra_proupregtx DASH_HFI_INIT =
  { "ProUpRegTx Payload", "dash.tx.proupregtx", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL };
static header_field_info hfi_msg_tx_extra_proupregtx_version DASH_HFI_INIT =
  { "Version", "dash.tx.proupregtx.version", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL };
static header_field_info hfi_msg_tx_extra_proupregtx_protxhash DASH_HFI_INIT =
  { "ProRegTx Hash", "dash.tx.proupregtx.protxhash", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL };
static header_field_info hfi_msg_tx_extra_proupregtx_mode DASH_HFI_INIT =
  { "Mode", "dash.tx.proupregtx.mode", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL };
static header_field_info hfi_msg_tx_extra_proupregtx_opr_pubkey DASH_HFI_INIT =
  { "Operator pubkey (BLS)", "dash.tx.proupregtx.pubkeyoperator", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL };
static header_field_info hfi_msg_tx_extra_proupregtx_keyid_voting DASH_HFI_INIT =
  { "Voting pubkey hash (ECDSA)", "dash.tx.proupregtx.keyidvoting", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL };
static header_field_info hfi_msg_tx_extra_proupregtx_script DASH_HFI_INIT =
  { "Payout script", "dash.tx.proupregtx.script", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL };
static header_field_info hfi_msg_tx_extra_proupregtx_script_size8 DASH_HFI_INIT =
  { "Size", "dash.tx.proupregtx.script.size", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL };
static header_field_info hfi_msg_tx_extra_proupregtx_script_size16 DASH_HFI_INIT =
  { "Size", "dash.tx.proupregtx.script.size", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL };
static header_field_info hfi_msg_tx_extra_proupregtx_script_size32 DASH_HFI_INIT =
  { "Size", "dash.tx.proupregtx.script.size", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL };
static header_field_info hfi_msg_tx_extra_proupregtx_script_size64 DASH_HFI_INIT =
  { "Size", "dash.tx.proupregtx.script.size", FT_UINT64, BASE_DEC, NULL, 0x0, NULL, HFILL };
static header_field_info hfi_msg_tx_extra_proupregtx_script_data DASH_HFI_INIT =
  { "Data", "dash.tx.proupregtx.script.data", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL };
static header_field_info hfi_msg_tx_extra_proupregtx_inputshash DASH_HFI_INIT =
  { "Inputs hash", "dash.tx.proupregtx.inputshash", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL };
static header_field_info hfi_msg_tx_extra_proupregtx_payloadsig_size8 DASH_HFI_INIT =
  { "Signature Size", "dash.tx.proupregtx.payloadsigsize", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL };
static header_field_info hfi_msg_tx_extra_proupregtx_payloadsig_size16 DASH_HFI_INIT =
  { "Signature Size", "dash.tx.proupregtx.payloadsigsize", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL };
static header_field_info hfi_msg_tx_extra_proupregtx_payloadsig_size32 DASH_HFI_INIT =
  { "Signature Size", "dash.tx.proupregtx.payloadsigsize", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL };
static header_field_info hfi_msg_tx_extra_proupregtx_payloadsig_size64 DASH_HFI_INIT =
  { "Signature Size", "dash.tx.proupregtx.payloadsigsize", FT_UINT64, BASE_DEC, NULL, 0x0, NULL, HFILL };
static header_field_info hfi_msg_tx_extra_proupregtx_payloadsig DASH_HFI_INIT =
  { "Signature", "dash.tx.proupregtx.payloadsig", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL };

/* tx.prouprevtx */
static header_field_info hfi_msg_tx_extra_prouprevtx DASH_HFI_INIT =
  { "ProUpRevTx Payload", "dash.tx.prouprevtx", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL };
static header_field_info hfi_msg_tx_extra_prouprevtx_version DASH_HFI_INIT =
  { "Version", "dash.tx.prouprevtx.version", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL };
static header_field_info hfi_msg_tx_extra_prouprevtx_protxhash DASH_HFI_INIT =
  { "ProRegTx Hash", "dash.tx.prouprevtx.protxhash", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL };
static header_field_info hfi_msg_tx_extra_prouprevtx_reason DASH_HFI_INIT =
  { "Version", "dash.tx.prouprevtx.reason", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL };
static header_field_info hfi_msg_tx_extra_prouprevtx_inputshash DASH_HFI_INIT =
  { "ProRegTx Hash", "dash.tx.prouprevtx.inputshash", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL };
static header_field_info hfi_msg_tx_extra_prouprevtx_payloadsig DASH_HFI_INIT =
  { "Signature", "dash.tx.prouprevtx.payloadsig", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL };

/* tx.cbtx */
static header_field_info hfi_msg_tx_extra_cbtx DASH_HFI_INIT =
  { "CbTx Payload", "dash.tx.cbtx", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL };
static header_field_info hfi_msg_tx_extra_cbtx_version DASH_HFI_INIT =
  { "Version", "dash.tx.cbtx.version", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL };
static header_field_info hfi_msg_tx_extra_cbtx_height DASH_HFI_INIT =
  { "Block Height", "dash.tx.cbtx.height", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL };
static header_field_info hfi_msg_tx_extra_cbtx_merkle_mn DASH_HFI_INIT =
  { "MN List merkle root", "dash.tx.cbtx.merklemn", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL };
static header_field_info hfi_msg_tx_extra_cbtx_merkle_quorum DASH_HFI_INIT =
  { "Active LLMQ merkle root", "dash.tx.cbtx.merklequorum", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL };

/* tx.qctx */
static header_field_info hfi_msg_tx_extra_qctx DASH_HFI_INIT =
  { "QcTx Payload", "dash.tx.qctx", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL };
static header_field_info hfi_msg_tx_extra_qctx_version DASH_HFI_INIT =
  { "Version", "dash.tx.qctx.version", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL };
static header_field_info hfi_msg_tx_extra_qctx_height DASH_HFI_INIT =
  { "Block Height", "dash.tx.qctx.height", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL };

/* block message */
static header_field_info hfi_msg_block_transactions8 DASH_HFI_INIT =
  { "Number of transactions", "dash.block.num_transactions", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL };

static header_field_info hfi_msg_block_transactions16 DASH_HFI_INIT =
  { "Number of transactions", "dash.block.num_transactions", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL };

static header_field_info hfi_msg_block_transactions32 DASH_HFI_INIT =
  { "Number of transactions", "dash.block.num_transactions", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL };

static header_field_info hfi_msg_block_transactions64 DASH_HFI_INIT =
  { "Number of transactions", "dash.block.num_transactions64", FT_UINT64, BASE_DEC, NULL, 0x0, NULL, HFILL };

static header_field_info hfi_dash_msg_block DASH_HFI_INIT =
  { "Block message", "dash.block", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL };

static header_field_info hfi_msg_block_version DASH_HFI_INIT =
  { "Block version", "dash.block.version", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL };

static header_field_info hfi_msg_block_prev_block DASH_HFI_INIT =
  { "Previous block", "dash.block.prev_block", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL };

static header_field_info hfi_msg_block_merkle_root DASH_HFI_INIT =
  { "Merkle root", "dash.block.merkle_root", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL };

static header_field_info hfi_msg_block_time DASH_HFI_INIT =
  { "Block timestamp", "dash.block.timestamp", FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL, NULL, 0x0, NULL, HFILL };

static header_field_info hfi_msg_block_bits DASH_HFI_INIT =
  { "Bits", "dash.block.bits", FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL };

static header_field_info hfi_msg_block_nonce DASH_HFI_INIT =
  { "Nonce", "dash.block.nonce", FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL };

/* headers message */
static header_field_info hfi_dash_msg_headers DASH_HFI_INIT =
  { "Headers message", "dash.headers", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL };

static header_field_info hfi_msg_headers_version DASH_HFI_INIT =
  { "Block version", "dash.headers.version", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL };

static header_field_info hfi_msg_headers_prev_block DASH_HFI_INIT =
  { "Previous block", "dash.headers.prev_block", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL };

static header_field_info hfi_msg_headers_merkle_root DASH_HFI_INIT =
  { "Merkle root", "dash.headers.merkle_root", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL };

static header_field_info hfi_msg_headers_time DASH_HFI_INIT =
  { "Block timestamp", "dash.headers.timestamp", FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL, NULL, 0x0, NULL, HFILL };

static header_field_info hfi_msg_headers_bits DASH_HFI_INIT =
  { "Bits", "dash.headers.bits", FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL };

static header_field_info hfi_msg_headers_nonce DASH_HFI_INIT =
  { "Nonce", "dash.headers.nonce", FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL };

static header_field_info hfi_msg_headers_count8 DASH_HFI_INIT =
  { "Count", "dash.headers.count", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL };

static header_field_info hfi_msg_headers_count16 DASH_HFI_INIT =
  { "Count", "dash.headers.count", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL };

static header_field_info hfi_msg_headers_count32 DASH_HFI_INIT =
  { "Count", "dash.headers.count", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL };

static header_field_info hfi_msg_headers_count64 DASH_HFI_INIT =
  { "Count", "dash.headers.count64", FT_UINT64, BASE_DEC, NULL, 0x0, NULL, HFILL };

/* ping message */
static header_field_info hfi_dash_msg_ping DASH_HFI_INIT =
  { "Ping message", "dash.ping", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL };

static header_field_info hfi_msg_ping_nonce DASH_HFI_INIT =
  { "Random nonce", "dash.ping.nonce", FT_UINT64, BASE_HEX, NULL, 0x0, NULL, HFILL };

/* pong message */
static header_field_info hfi_dash_msg_pong DASH_HFI_INIT =
  { "Pong message", "dash.pong", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL };

static header_field_info hfi_msg_pong_nonce DASH_HFI_INIT =
  { "Random nonce", "dash.pong.nonce", FT_UINT64, BASE_HEX, NULL, 0x0, NULL, HFILL };

/* reject message */
static header_field_info hfi_dash_msg_reject DASH_HFI_INIT =
  { "Reject message", "dash.reject", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL };

static header_field_info hfi_msg_reject_message DASH_HFI_INIT =
  { "Message rejected", "dash.reject.message", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL };

static header_field_info hfi_msg_reject_reason DASH_HFI_INIT =
  { "Reason", "dash.reject.reason", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL };

static header_field_info hfi_msg_reject_ccode DASH_HFI_INIT =
  { "CCode", "dash.reject.ccode", FT_UINT8, BASE_HEX, VALS(reject_ccode), 0x0, NULL, HFILL };

static header_field_info hfi_msg_reject_data DASH_HFI_INIT =
  { "Data", "dash.reject.data", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL };

/* filterload message */
static header_field_info hfi_dash_msg_filterload DASH_HFI_INIT =
  { "Filterload message", "dash.filterload", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL };

static header_field_info hfi_msg_filterload_filter DASH_HFI_INIT =
  { "Filter", "dash.filterload.filter", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL };

static header_field_info hfi_msg_filterload_nhashfunc DASH_HFI_INIT =
  { "nHashFunc", "dash.filterload.nhashfunc", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL };

static header_field_info hfi_msg_filterload_ntweak DASH_HFI_INIT =
  { "nTweak", "dash.filterload.ntweak", FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL };

static header_field_info hfi_msg_filterload_nflags DASH_HFI_INIT =
  { "nFlags", "dash.filterload.nflags", FT_UINT8, BASE_HEX, VALS(filterload_nflags), 0x0, NULL, HFILL };

/* filteradd message */
static header_field_info hfi_dash_msg_filteradd DASH_HFI_INIT =
  { "Filteradd message", "dash.filteradd", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL };

static header_field_info hfi_msg_filteradd_data DASH_HFI_INIT =
  { "Data", "dash.filteradd.data", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL };

/* merkleblock message */
static header_field_info hfi_dash_msg_merkleblock DASH_HFI_INIT =
  { "Merkleblock message", "dash.merkleblock", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL };

static header_field_info hfi_msg_merkleblock_transactions DASH_HFI_INIT =
  { "Number of transactions", "dash.merkleblock.num_transactions", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL };

static header_field_info hfi_msg_merkleblock_version DASH_HFI_INIT =
  { "Block version", "dash.merkleblock.version", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL };

static header_field_info hfi_msg_merkleblock_prev_block DASH_HFI_INIT =
  { "Previous block", "dash.merkleblock.prev_block", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL };

static header_field_info hfi_msg_merkleblock_merkle_root DASH_HFI_INIT =
  { "Merkle root", "dash.merkleblock.merkle_root", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL };

static header_field_info hfi_msg_merkleblock_time DASH_HFI_INIT =
  { "Block timestamp", "dash.merkleblock.timestamp", FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL, NULL, 0x0, NULL, HFILL };

static header_field_info hfi_msg_merkleblock_bits DASH_HFI_INIT =
  { "Bits", "dash.merkleblock.bits", FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL };

static header_field_info hfi_msg_merkleblock_nonce DASH_HFI_INIT =
  { "Nonce", "dash.merkleblock.nonce", FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL };

static header_field_info hfi_msg_merkleblock_hashes_count8 DASH_HFI_INIT =
  { "Count", "dash.merkleblock.hashes.count", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL };

static header_field_info hfi_msg_merkleblock_hashes_count16 DASH_HFI_INIT =
  { "Count", "dash.merkleblock.hashes.count", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL };

static header_field_info hfi_msg_merkleblock_hashes_count32 DASH_HFI_INIT =
  { "Count", "dash.merkleblock.hashes.count", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL };

static header_field_info hfi_msg_merkleblock_hashes_count64 DASH_HFI_INIT =
  { "Count", "dash.merkleblock.hashes.count64", FT_UINT64, BASE_DEC, NULL, 0x0, NULL, HFILL };

static header_field_info hfi_msg_merkleblock_hashes_hash DASH_HFI_INIT =
  { "Hash", "dash.merkleblock.hashes.hash", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL };

static header_field_info hfi_msg_merkleblock_flags_size8 DASH_HFI_INIT =
  { "Size", "dash.merkleblock.flags.count", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL };

static header_field_info hfi_msg_merkleblock_flags_size16 DASH_HFI_INIT =
  { "Size", "dash.merkleblock.flags.count", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL };

static header_field_info hfi_msg_merkleblock_flags_size32 DASH_HFI_INIT =
  { "Size", "dash.merkleblock.flags.count", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL };

static header_field_info hfi_msg_merkleblock_flags_size64 DASH_HFI_INIT =
  { "Size", "dash.merkleblock.flags.count64", FT_UINT64, BASE_DEC, NULL, 0x0, NULL, HFILL };

static header_field_info hfi_msg_merkleblock_flags_data DASH_HFI_INIT =
  { "Data", "dash.merkleblock.flags.data", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL };

/* services */
static header_field_info hfi_services_network DASH_HFI_INIT =
  { "Network", "dash.services.network", FT_BOOLEAN, 32, TFS(&tfs_set_notset), 0x1, NULL, HFILL };

static header_field_info hfi_services_getutxo DASH_HFI_INIT =
  { "Get UTXO", "dash.services.getutxo", FT_BOOLEAN, 32, TFS(&tfs_set_notset), 0x2, NULL, HFILL };

static header_field_info hfi_services_bloom DASH_HFI_INIT =
  { "Bloom filter", "dash.services.bloom", FT_BOOLEAN, 32, TFS(&tfs_set_notset), 0x4, NULL, HFILL };

/* address */
static header_field_info hfi_address_services DASH_HFI_INIT =
  { "Node services", "dash.address.services", FT_UINT64, BASE_HEX, NULL, 0x0, NULL, HFILL };

static header_field_info hfi_address_address DASH_HFI_INIT =
  { "Node address", "dash.address.address", FT_IPv6, BASE_NONE, NULL, 0x0, NULL, HFILL };

static header_field_info hfi_address_port DASH_HFI_INIT =
  { "Node port", "dash.address.port", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL };


/* blocktxn message */
static header_field_info hfi_dash_msg_blocktxn DASH_HFI_INIT =
  { "blocktxn message", "dash.blocktxn", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL };
static header_field_info hfi_msg_blocktxn_hash DASH_HFI_INIT =
  { "Block Hash", "dash.blocktxn.blockhash", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL };
static header_field_info hfi_msg_blocktxn_tx_count8 DASH_HFI_INIT =
  { "Transactions Provided", "dash.blocktxn.txcount", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL };
static header_field_info hfi_msg_blocktxn_tx_count16 DASH_HFI_INIT =
  { "Transactions Provided", "dash.blocktxn.txcount", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL };
static header_field_info hfi_msg_blocktxn_tx_count32 DASH_HFI_INIT =
  { "Transactions Provided", "dash.blocktxn.txcount", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL };
static header_field_info hfi_msg_blocktxn_tx_count64 DASH_HFI_INIT =
  { "Transactions Provided", "dash.blocktxn.txcount64", FT_UINT64, BASE_DEC, NULL, 0x0, NULL, HFILL };

/* cmpctblock message */
static header_field_info hfi_dash_msg_cmpctblock DASH_HFI_INIT =
  { "cmpctblock message", "dash.cmpctblock", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL };
static header_field_info hfi_msg_cmpctblock_version DASH_HFI_INIT =
  { "Block version", "dash.cmpctblock.version", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL };
static header_field_info hfi_msg_cmpctblock_prev_block DASH_HFI_INIT =
  { "Previous block", "dash.cmpctblock.prev_block", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL };
static header_field_info hfi_msg_cmpctblock_merkle_root DASH_HFI_INIT =
  { "Merkle root", "dash.cmpctblock.merkle_root", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL };
static header_field_info hfi_msg_cmpctblock_time DASH_HFI_INIT =
  { "Block timestamp", "dash.cmpctblock.timestamp", FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL, NULL, 0x0, NULL, HFILL };
static header_field_info hfi_msg_cmpctblock_bits DASH_HFI_INIT =
  { "Bits", "dash.cmpctblock.bits", FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL };
static header_field_info hfi_msg_cmpctblock_nonce DASH_HFI_INIT =
  { "Nonce", "dash.cmpctblock.nonce", FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL };
static header_field_info hfi_msg_cmpctblock_shortids_nonce DASH_HFI_INIT =
  { "Short IDs Nonce", "dash.cmpctblock.shortidsnonce", FT_UINT64, BASE_DEC, NULL, 0x0, NULL, HFILL };
static header_field_info hfi_msg_cmpctblock_shortids_count8 DASH_HFI_INIT =
  { "Short IDs Length", "dash.cmpctblock.shortidscount", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL };
static header_field_info hfi_msg_cmpctblock_shortids_count16 DASH_HFI_INIT =
  { "Short IDs Length", "dash.cmpctblock.shortidscount", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL };
static header_field_info hfi_msg_cmpctblock_shortids_count32 DASH_HFI_INIT =
  { "Short IDs Length", "dash.cmpctblock.shortidscount", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL };
static header_field_info hfi_msg_cmpctblock_shortids_count64 DASH_HFI_INIT =
  { "Short IDs Length", "dash.cmpctblock.shortidscount64", FT_UINT64, BASE_DEC, NULL, 0x0, NULL, HFILL };
static header_field_info hfi_msg_cmpctblock_shortids DASH_HFI_INIT =
  { "Short IDs", "dash.cmpctblock.shortids", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL };
static header_field_info hfi_msg_cmpctblock_shortids_id DASH_HFI_INIT =
  { "Short IDs", "dash.cmpctblock.shortids.id", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL };
static header_field_info hfi_msg_cmpctblock_prefilledtxn_count8 DASH_HFI_INIT =
  { "Prefilled Transaction Length", "dash.cmpctblock.prefilledtxncount", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL };
static header_field_info hfi_msg_cmpctblock_prefilledtxn_count16 DASH_HFI_INIT =
  { "Prefilled Transaction Length", "dash.cmpctblock.prefilledtxncount", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL };
static header_field_info hfi_msg_cmpctblock_prefilledtxn_count32 DASH_HFI_INIT =
  { "Prefilled Transaction Length", "dash.cmpctblock.prefilledtxncount", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL };
static header_field_info hfi_msg_cmpctblock_prefilledtxn_count64 DASH_HFI_INIT =
  { "Prefilled Transaction Length", "dash.cmpctblock.prefilledtxncount64", FT_UINT64, BASE_DEC, NULL, 0x0, NULL, HFILL };
static header_field_info hfi_msg_cmpctblock_prefilledtx DASH_HFI_INIT =
  { "Prefilled Transaction", "dash.cmpctblock.prefilledtx", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL };
static header_field_info hfi_msg_cmpctblock_prefilledtx_index8 DASH_HFI_INIT =
  { "Prefilled Transaction Index", "dash.cmpctblock.prefilledtx.index", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL };
static header_field_info hfi_msg_cmpctblock_prefilledtx_index16 DASH_HFI_INIT =
  { "Prefilled Transaction Index", "dash.cmpctblock.prefilledtx.index", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL };
static header_field_info hfi_msg_cmpctblock_prefilledtx_index32 DASH_HFI_INIT =
  { "Prefilled Transaction Index", "dash.cmpctblock.prefilledtx.index", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL };
static header_field_info hfi_msg_cmpctblock_prefilledtx_index64 DASH_HFI_INIT =
  { "Prefilled Transaction Index", "dash.cmpctblock.prefilledtx.index64", FT_UINT64, BASE_DEC, NULL, 0x0, NULL, HFILL };

/* getblocktxn message */
static header_field_info hfi_dash_msg_getblocktxn DASH_HFI_INIT =
  { "getblocktxn message", "dash.getblocktxn", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL };
static header_field_info hfi_msg_getblocktxn_hash DASH_HFI_INIT =
  { "Block Hash", "dash.getblocktxn.blockhash", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL };
static header_field_info hfi_msg_getblocktxn_tx_count8 DASH_HFI_INIT =
  { "Index Length", "dash.getblocktxn.txcount", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL };
static header_field_info hfi_msg_getblocktxn_tx_count16 DASH_HFI_INIT =
  { "Index Length", "dash.getblocktxn.txcount", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL };
static header_field_info hfi_msg_getblocktxn_tx_count32 DASH_HFI_INIT =
  { "Index Length", "dash.getblocktxn.txcount", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL };
static header_field_info hfi_msg_getblocktxn_tx_count64 DASH_HFI_INIT =
  { "Index Length", "dash.getblocktxn.txcount64", FT_UINT64, BASE_DEC, NULL, 0x0, NULL, HFILL };
static header_field_info hfi_msg_getblocktxn_tx_index8 DASH_HFI_INIT =
  { "Index", "dash.getblocktxn.txindex", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL };
static header_field_info hfi_msg_getblocktxn_tx_index16 DASH_HFI_INIT =
  { "Index", "dash.getblocktxn.txindex", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL };
static header_field_info hfi_msg_getblocktxn_tx_index32 DASH_HFI_INIT =
  { "Index", "dash.getblocktxn.txindex", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL };
static header_field_info hfi_msg_getblocktxn_tx_index64 DASH_HFI_INIT =
  { "Index", "dash.getblocktxn.txindex64", FT_UINT64, BASE_DEC, NULL, 0x0, NULL, HFILL };

/* sendcmpct message */
static header_field_info hfi_dash_msg_sendcmpct DASH_HFI_INIT =
  { "sendcmpct message", "dash.sendcmpct", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL };
static header_field_info hfi_msg_sendcmpct_announce DASH_HFI_INIT =
  { "Block announce type", "dash.sendcmpct.announce", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL };
static header_field_info hfi_msg_sendcmpct_version DASH_HFI_INIT =
  { "Compact block version", "dash.sendcmpct.version", FT_UINT64, BASE_HEX, NULL, 0x0, NULL, HFILL };

/* variable string */
static header_field_info hfi_string_value DASH_HFI_INIT =
  { "String value", "dash.string.value", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL };

static header_field_info hfi_string_varint_count8 DASH_HFI_INIT =
  { "Count", "dash.string.count", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL };

static header_field_info hfi_string_varint_count16 DASH_HFI_INIT =
  { "Count", "dash.string.count", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL };

static header_field_info hfi_string_varint_count32 DASH_HFI_INIT =
  { "Count", "dash.string.count", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL };

static header_field_info hfi_string_varint_count64 DASH_HFI_INIT =
  { "Count", "dash.string.count64", FT_UINT64, BASE_DEC, NULL, 0x0, NULL, HFILL };

/* variable data */
static header_field_info hfi_data_value DASH_HFI_INIT =
  { "Data", "dash.data.value", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL };

static header_field_info hfi_data_varint_count8 DASH_HFI_INIT =
  { "Count", "dash.data.count", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL };

static header_field_info hfi_data_varint_count16 DASH_HFI_INIT =
  { "Count", "dash.data.count", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL };

static header_field_info hfi_data_varint_count32 DASH_HFI_INIT =
  { "Count", "dash.data.count", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL };

static header_field_info hfi_data_varint_count64 DASH_HFI_INIT =
  { "Count", "dash.data.count64", FT_UINT64, BASE_DEC, NULL, 0x0, NULL, HFILL };

/* Special Txs */
static header_field_info hfi_msg_specialtx_payload_version DASH_HFI_INIT =
  { "Special Transaction payload version", "dash.specialtx.payload.version", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL };

static header_field_info hfi_dash_msg_subtx DASH_HFI_INIT =
    { "Subscription Transaction payload", "dash.subtx.payload", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL };

static header_field_info hfi_dash_msg_subtx_username DASH_HFI_INIT =
  { "Username", "dash.subtx.payload.username", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL };

/* mnb - Masternode Broadcast
	Whenever a masternode comes online or a client is syncing,
	they will send this message which describes the masternode entry and how to validate messages from it.

	Field Size 	Field Name 			Data type 		Description
	36 		outpoint			COutPoint		The unspent output which is holding 1000 DASH
	# 		addr 				CService 		Address of the main 1000 DASH unspent output
	33-65 		pubKeyCollateralAddress 	CPubKey 		CPubKey of the main 1000 DASH unspent output
	33-65 		pubKeyMasternode 		CPubKey 		CPubKey of the secondary signing key (For all other messaging other than announce message)
	71-73 		sig 				char[] 			Signature of this message
	8 		sigTime 			int64_t 		Time which the signature was created
	4 		nProtocolVersion 		int 			The protocol version of the masternode
	# 		lastPing 			CMasternodePing 	The last known ping of the masternode
	8 		nLastDsq 			int64_t 		The last time the masternode sent a DSQ message (for mixing) (DEPRECATED)
*/
static header_field_info hfi_dash_msg_mnb DASH_HFI_INIT =
  { "Masternode Broadcast message", "dash.mnb", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL };

static header_field_info hfi_msg_mnb_outpoint DASH_HFI_INIT =
  { "Masternode collateral output", "dash.mnb.outpoint", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL };

static header_field_info hfi_msg_mnb_pubkey_collateral DASH_HFI_INIT =
  { "Public Key of Masternode Collateral", "dash.mnb.collateralpubkey", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL };

static header_field_info hfi_msg_mnb_pubkey_masternode DASH_HFI_INIT =
  { "Public Key of Masternode", "dash.mnb.masternodepubkey", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL };

static header_field_info hfi_msg_mnb_vchsig DASH_HFI_INIT =
  { "Message Signature", "dash.mnb.vchsig", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL };

static header_field_info hfi_msg_mnb_sigtime DASH_HFI_INIT =
  { "Signature timestamp", "dash.mnb.sigtime", FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL, NULL, 0x0, NULL, HFILL };

static header_field_info hfi_msg_mnb_protocol_version DASH_HFI_INIT =
  { "Protocol Version", "dash.mnb.protocolversion", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL };

/* mnp - Masternode Ping
	Field Size 	Field Name 	Data type 	Description
	-----------------------------------------------
	36 		outpoint	COutPoint	The unspent output of the masternode which is signing the message
	32 		blockHash 	uint256 	Current chaintip blockhash minus 12
	8 		sigTime 	int64_t 	Signature time for this ping
	71-73 		vchSig 		char[] 		Signature of this message by masternode (verifiable via pubKeyMasternode)
*/
static header_field_info hfi_dash_msg_mnp DASH_HFI_INIT =
  { "Masternode Ping message", "dash.mnp", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL };

static header_field_info hfi_msg_mnp_outpoint DASH_HFI_INIT =
  { "Masternode collateral output", "dash.mnp.outpoint", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL };

static header_field_info hfi_msg_mnp_blockhash DASH_HFI_INIT =
  { "Chaintip block hash", "dash.mnp.blockhash", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL };

static header_field_info hfi_msg_mnp_sigtime DASH_HFI_INIT =
  { "Signature timestamp", "dash.mnp.sigtime", FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL, NULL, 0x0, NULL, HFILL };

static header_field_info hfi_msg_mnp_vchsig DASH_HFI_INIT =
  { "Masternode Signature", "dash.mnp.vchsig", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL };

/* mnw - Masternode Payment Vote
	When a new block is found on the network, a masternode quorum will be determined and
	those 10 selected masternodes will issue a masternode payment vote message to pick the next winning node.

	Field Size 	Field Name 	Data type 	Description
	36 		outpoint	COutPoint	The unspent output of the masternode which is signing the message
	4 		nBlockHeight 	int 		The blockheight which the payee should be paid
	? 		payeeAddress 	CScript 	The address to pay to
	71-73 		sig 		char[] 		Signature of the masternode which is signing the message
*/
static header_field_info hfi_dash_msg_mnw DASH_HFI_INIT =
  { "Masternode Payment Vote message", "dash.mnw", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL };

static header_field_info hfi_msg_mnw_outpoint DASH_HFI_INIT =
  { "Masternode collateral output", "dash.mnw.outpoint", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL };

static header_field_info hfi_dash_msg_mnw_payheight DASH_HFI_INIT =
  { "Block pay height", "dash.mnw.height", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL };

static header_field_info hfi_msg_mnw_payeeaddress DASH_HFI_INIT =
  { "Payee Address", "dash.mnw.payeeaddress", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL };

static header_field_info hfi_msg_mnw_sig DASH_HFI_INIT =
  { "Masternode Signature", "dash.mnw.sig", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL };

/* mnwb - Masternode Payment Block

*/
static header_field_info hfi_dash_msg_mnwb DASH_HFI_INIT =
  { "Masternode Payment Block message", "dash.mnwb", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL };

/* mnv - Masternode Verify

*/
static header_field_info hfi_dash_msg_mnv DASH_HFI_INIT =
  { "Masternode Verify message", "dash.mnv", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL };

static header_field_info hfi_msg_mnv_outpoint1 DASH_HFI_INIT =
  { "Masternode 1 collateral output", "dash.mnv.outpoint1", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL };

static header_field_info hfi_msg_mnv_outpoint2 DASH_HFI_INIT =
  { "Masternode 1 collateral output", "dash.mnv.outpoint2", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL };

static header_field_info hfi_msg_mnv_nonce DASH_HFI_INIT =
  { "Nonce", "dash.mnv.nonce", FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL };

static header_field_info hfi_msg_mnv_height DASH_HFI_INIT =
  { "Block height", "dash.mnv.height", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL };

static header_field_info hfi_msg_mnv_vchsig1 DASH_HFI_INIT =
  { "Masternode Signature 1", "dash.mnv.vchsig1", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL };

static header_field_info hfi_msg_mnv_vchsig2 DASH_HFI_INIT =
  { "Masternode Signature 2", "dash.mnv.vchsig2", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL };

/* dstx - Darksend Broadcast
	Masternodes can broadcast subsidised transactions without fees for the sake of security in mixing. This is done via the DSTX message.
*/
static header_field_info hfi_dash_msg_dstx DASH_HFI_INIT =
  { "Darksend Broadcast message", "dash.dstx", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL };

static header_field_info hfi_msg_dstx_outpoint DASH_HFI_INIT =
  { "Masternode collateral output", "dash.dstx.outpoint", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL };

static header_field_info hfi_msg_dstx_vchsig DASH_HFI_INIT =
  { "Masternode Signature", "dash.dstx.vchsig", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL };

static header_field_info hfi_msg_dstx_sigtime DASH_HFI_INIT =
  { "Signature timestamp", "dash.dstx.sigtime", FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL, NULL, 0x0, NULL, HFILL };

/* dssu - Mixing pool status update
	Mixing pool status update
*/
static header_field_info hfi_dash_msg_dssu DASH_HFI_INIT =
  { "Mixing Pool Status Update message", "dash.dssu", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL };

static header_field_info hfi_dash_msg_dssu_session_id DASH_HFI_INIT =
  { "Session ID", "dash.dssu.session", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL };

static header_field_info hfi_dash_msg_dssu_state DASH_HFI_INIT =
  { "State", "dash.dssu.state", FT_UINT32, BASE_DEC, VALS(pool_state), 0x0, NULL, HFILL };

static header_field_info hfi_dash_msg_dssu_entries DASH_HFI_INIT =
  { "Entries", "dash.dssu.entries", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL };

static header_field_info hfi_dash_msg_dssu_status_update DASH_HFI_INIT =
  { "Status Update", "dash.dssu.update", FT_UINT32, BASE_DEC, VALS(pool_status_update), 0x0, NULL, HFILL };

static header_field_info hfi_dash_msg_dssu_message_id DASH_HFI_INIT =
  { "Message ID", "dash.dssu.message", FT_UINT32, BASE_DEC, VALS(pool_message), 0x0, NULL, HFILL };

/* dsq message - Darksend Queue
	Field Size 	Field Name 	Data type 	Description
	4 		nDenom 		int 		Which denomination is allowed in this mixing session
	4 		nInputCount 		int 		Number of inputs required for this mixing session (DEPRECATED)
	36 		outpoint	COutPoint	The unspent output of the masternode which is signing the message
	8 		nTime 		int64_t 		The time this DSQ was created
	1 		fReady 		bool 		If the mixing pool is ready to be executed
	66 		vchSig 		char[] 		Signature of this message by masternode (verifiable via pubKeyMasternode)
*/
static header_field_info hfi_dash_msg_dsq DASH_HFI_INIT =
  { "Darksend Queue message", "dash.dsq", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL };

static header_field_info hfi_msg_dsq_denom DASH_HFI_INIT =
  { "Denomination", "dash.dsq.denom", FT_UINT32, BASE_DEC, VALS(private_send_denomination), 0x0, NULL, HFILL };

static header_field_info hfi_msg_dsq_outpoint DASH_HFI_INIT =
  { "Masternode collateral output", "dash.dsq.outpoint", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL };

static header_field_info hfi_msg_dsq_vin_prev_outp_hash DASH_HFI_INIT =
  { "Hash", "dash.dsq.vin.prev_output.hash", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL };

static header_field_info hfi_msg_dsq_vin_prev_outp_index DASH_HFI_INIT =
  { "Index", "dash.dsq.vin.prev_output.index", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL };

static header_field_info hfi_msg_dsq_vin_seq DASH_HFI_INIT =
  { "Sequence", "dash.dsq.vin.seq", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL };

static header_field_info hfi_msg_dsq_time DASH_HFI_INIT =
  { "Create Time", "dash.dsq.time", FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL, NULL, 0x0, NULL, HFILL };

static header_field_info hfi_msg_dsq_ready DASH_HFI_INIT =
  { "Ready", "dash.dsq.ready", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL };

static header_field_info hfi_msg_dsq_vchsig DASH_HFI_INIT =
  { "Masternode Signature", "dash.dsq.vchsig", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL };

/* dsa - Darksend Accept
	Response to DSQ message which allows the user to join a mixing pool
*/
static header_field_info hfi_dash_msg_dsa DASH_HFI_INIT =
  { "Darksend Accept message", "dash.dsa", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL };

static header_field_info hfi_dash_msg_dsa_denom DASH_HFI_INIT =
  { "Denomination", "dash.dsa.denom", FT_UINT32, BASE_DEC, VALS(private_send_denomination), 0x0, NULL, HFILL };

/* dsi - Darksend Entry
	When queue is ready user is expected to send his entry to start actual mixing
*/
static header_field_info hfi_dash_msg_dsi DASH_HFI_INIT =
  { "Darksend Entry message", "dash.dsi", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL };

/* dsf - Darksend Final Transaction

*/
static header_field_info hfi_dash_msg_dsf DASH_HFI_INIT =
  { "Darksend Final Tx message", "dash.dsf", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL };

static header_field_info hfi_dash_msg_dsf_session_id DASH_HFI_INIT =
  { "Session ID", "dash.dsf.session", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL };

/* dsc - Darksend Complete

*/
static header_field_info hfi_dash_msg_dsc DASH_HFI_INIT =
  { "Darksend Complete message", "dash.dsc", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL };

static header_field_info hfi_dash_msg_dsc_session_id DASH_HFI_INIT =
  { "Session ID", "dash.dsc.session", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL };

static header_field_info hfi_dash_msg_dsc_message_id DASH_HFI_INIT =
  { "Message ID", "dash.dsc.message", FT_UINT32, BASE_DEC, VALS(pool_message), 0x0, NULL, HFILL };

/* dss - Darksend Sign Final Transaction
	User's signed inputs for a group transaction in a mixing session
*/
static header_field_info hfi_dash_msg_dss DASH_HFI_INIT =
  { "Darksend Sign Final Tx message", "dash.dss", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL };

/* ix - Tx Lock Request
	Transaction Lock Request, serialization is the same as for CTransaction.
*/
static header_field_info hfi_dash_msg_ix DASH_HFI_INIT =
  { "Tx Lock Request message", "dash.ix", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL };

/* txlvote - Tx Lock Vote
	Transaction Lock Vote
*/
static header_field_info hfi_dash_msg_txlvote DASH_HFI_INIT =
  { "Transaction Lock Vote message", "dash.txlvote", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL };

static header_field_info hfi_msg_txlvote_txhash DASH_HFI_INIT =
  { "Transaction hash", "dash.txlvote.txhash", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL };

static header_field_info hfi_msg_txlvote_outpoint DASH_HFI_INIT =
  { "Output to lock", "dash.txlvote.outpoint", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL };

static header_field_info hfi_msg_txlvote_outpoint_masternode DASH_HFI_INIT =
  { "Masternode output", "dash.txlvote.outpoint", FT_NONE, BASE_NONE, NULL, 0x0, "The utxo of the masternode which is signing the vote", HFILL };
static header_field_info hfi_msg_txlvote_quorumModHash DASH_HFI_INIT =
  { "Quorum Modifier hash", "dash.txlvote.quorumhash", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL };

static header_field_info hfi_msg_txlvote_proTxHash DASH_HFI_INIT =
  { "Masternode ProRegTx hash", "dash.txlvote.protxhash", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL };
static header_field_info hfi_msg_txlvote_vchsig DASH_HFI_INIT =
  { "Masternode Signature", "dash.txlvote.vchsig", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL };

/* govobj - Governance Object
	A proposal, contract or setting.
*/
static header_field_info hfi_dash_msg_govobj DASH_HFI_INIT =
  { "Governance Object message", "dash.govobj", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL };

static header_field_info hfi_msg_govobj_parenthash DASH_HFI_INIT =
  { "Parent hash", "dash.govobj.parenthash", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL };

static header_field_info hfi_msg_govobj_revision DASH_HFI_INIT =
  { "Revision", "dash.govobj.revision", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL };

static header_field_info hfi_msg_govobj_createtime DASH_HFI_INIT =
  { "Created timestamp", "dash.govobj.createtime", FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL, NULL, 0x0, NULL, HFILL };

static header_field_info hfi_msg_govobj_collateralhash DASH_HFI_INIT =
  { "Collateral hash", "dash.govobj.collateralhash", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL };

/* strData (0-16384) */
static header_field_info hfi_msg_govobj_strdata DASH_HFI_INIT =
  { "Data", "dash.govobj.strdata", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL };

static header_field_info hfi_msg_govobj_object_type DASH_HFI_INIT =
  { "Object Type", "dash.govobj.objecttype", FT_UINT32, BASE_DEC, VALS(governance_object), 0x0, NULL, HFILL };

static header_field_info hfi_msg_govobj_outpoint DASH_HFI_INIT =
  { "Masternode collateral output", "dash.govobj.outpoint", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL };

static header_field_info hfi_msg_govobj_vchsig DASH_HFI_INIT =
  { "Masternode Signature", "dash.govobj.vchsig", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL };


/* govobjvote - Governance Vote
	Masternodes use governance voting in response to new proposals, contracts, settings or finalized budgets.
*/
static header_field_info hfi_dash_msg_govobjvote DASH_HFI_INIT =
  { "Masternode Governance Vote message", "dash.govobjvote", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL };

static header_field_info hfi_msg_govobjvote_outpoint DASH_HFI_INIT =
  { "Masternode collateral output", "dash.govobjvote.outpoint", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL };

static header_field_info hfi_msg_govobjvote_parenthash DASH_HFI_INIT =
  { "Parent hash", "dash.govobjvote.parenthash", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL };

static header_field_info hfi_msg_govobjvote_voteoutcome DASH_HFI_INIT =
  { "Vote Outcome", "dash.govobjvote.voteoutcome", FT_UINT32, BASE_DEC, VALS(vote_outcome), 0x0, NULL, HFILL };

static header_field_info hfi_msg_govobjvote_votesignal DASH_HFI_INIT =
  { "Vote Signal", "dash.govobjvote.votesignal", FT_UINT32, BASE_DEC, VALS(vote_signal), 0x0, NULL, HFILL };

static header_field_info hfi_msg_govobjvote_createtime DASH_HFI_INIT =
  { "Vote created timestamp", "dash.govobjvote.createtime", FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL, NULL, 0x0, NULL, HFILL };

static header_field_info hfi_msg_govobjvote_vchsig DASH_HFI_INIT =
  { "Masternode Signature", "dash.govobjvote.vchsig", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL };


/* govsync - Governance Sync

*/
static header_field_info hfi_dash_msg_govsync DASH_HFI_INIT =
  { "Masternode Governance Sync message", "dash.govsync", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL };

static header_field_info hfi_msg_govsync_hash DASH_HFI_INIT =
  { "Hash", "dash.govsync.hash", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL };

static header_field_info hfi_dash_msg_govsync_bloom_filter DASH_HFI_INIT =
  { "Bloom Filter", "dash.govsync.bloomfilter", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL };

/* spork - Spork
	No documentation available
*/
static header_field_info hfi_dash_msg_spork DASH_HFI_INIT =
  { "Spork message", "dash.spork", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL };

static header_field_info hfi_dash_msg_spork_id DASH_HFI_INIT =
  { "Spork ID", "dash.spork.id", FT_UINT32, BASE_DEC, VALS(spork_description), 0x0, NULL, HFILL };

static header_field_info hfi_dash_msg_spork_value DASH_HFI_INIT =
  { "Value", "dash.spork.value", FT_UINT64, BASE_DEC, NULL, 0x0, NULL, HFILL };

static header_field_info hfi_dash_msg_spork_sigtime DASH_HFI_INIT =
  { "Signature timestamp", "dash.spork.sigtime", FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL, NULL, 0x0, NULL, HFILL };

static header_field_info hfi_dash_msg_spork_vchsig DASH_HFI_INIT =
  { "Masternode Signature", "dash.spork.vchsig", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL };

/* dseg - ???
	No documentation available
    Per src/masternodeman.c - DsegUpdate:
    36 		outpoint	COutPoint	The unspent output of the masternode which is signing the message
*/
static header_field_info hfi_dash_msg_dseg DASH_HFI_INIT =
  { "Dseg message", "dash.dseg", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL };

/* ssc - Sync Status Count
	No documentation available
    Per src/masternode-sync.c - PushMessage(NetMsgType::SYNCSTATUSCOUNT, [ItemID], [Count]):
        Item IDs defined at top of src/masternode-sync.h
*/
static header_field_info hfi_dash_msg_ssc DASH_HFI_INIT =
  { "Sync Status Count message", "dash.ssc", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL };

static header_field_info hfi_msg_dseg_outpoint DASH_HFI_INIT =
  { "Masternode collateral output", "dash.dseg.outpoint", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL };

static header_field_info hfi_dash_msg_ssc_item_id DASH_HFI_INIT =
  { "Item ID", "dash.ssc.itemid", FT_UINT32, BASE_DEC, VALS(masternode_sync_item_id), 0x0, NULL, HFILL };

static header_field_info hfi_dash_msg_ssc_count DASH_HFI_INIT =
  { "Count", "dash.ssc.count", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL };

/* mnget - Masternode Payment Sync
	No documentation available
    Per src/masternode-sync.c - PushMessage(NetMsgType::MASTERNODEPAYMENTSYNC, nMnCount):
    4       nMnCount        int             Number of masternodes? // REMOVED in protocol version 70210
*/
static header_field_info hfi_dash_msg_mnget DASH_HFI_INIT =
  { "Masternode Payment Sync message", "dash.mnget", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL };

// Removed in protocol version 70210
//static header_field_info hfi_dash_msg_mnget_count32 DASH_HFI_INIT =
//  { "Count", "dash.mnget.count", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL };

/* getmnlistd message: */
static header_field_info hfi_dash_msg_getmnlistd DASH_HFI_INIT =
  { "getmnlistd message", "dash.getmnlistd", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL };
static header_field_info hfi_msg_getmnlistd_baseblockhash DASH_HFI_INIT =
  { "Base block hash", "dash.getmnlistd.baseblockhash", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL };
static header_field_info hfi_msg_getmnlistd_blockhash DASH_HFI_INIT =
  { "Block hash", "dash.getmnlistd.blockhash", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL };

/* mnlistdiff message: */
static header_field_info hfi_dash_msg_mnlistdiff DASH_HFI_INIT =
  { "mnlistdiff message", "dash.mnlistdiff", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL };

/* senddsq message: */
static header_field_info hfi_dash_msg_senddsq DASH_HFI_INIT =
  { "senddsq message", "dash.senddsq", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL };
static header_field_info hfi_msg_senddsq_enable DASH_HFI_INIT =
  { "PrivateSend participation", "dash.senddsq.enable", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL };

/* clsig message: */
static header_field_info hfi_dash_msg_clsig DASH_HFI_INIT =
  { "clsig message", "dash.clsig", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL };
static header_field_info hfi_msg_clsig_height DASH_HFI_INIT =
  { "Block Height", "dash.clsig.start_height", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL };
static header_field_info hfi_msg_clsig_blockhash DASH_HFI_INIT =
  { "Block Hash", "dash.clsig.protxhash", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL };
static header_field_info hfi_msg_clsig_sig DASH_HFI_INIT =
  { "LLMQ BLS Signature", "dash.clsig.blssignature", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL };

/* islock message: */
static header_field_info hfi_dash_msg_islock DASH_HFI_INIT =
  { "islock message", "dash.islock", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL };
static header_field_info hfi_msg_islock_input_count8 DASH_HFI_INIT =
  { "Number of inputs", "dash.islock.inputnum", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL };
static header_field_info hfi_msg_islock_input_count16 DASH_HFI_INIT =
  { "Number of inputs", "dash.islock.inputnum", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL };
static header_field_info hfi_msg_islock_input_count32 DASH_HFI_INIT =
  { "Number of inputs", "dash.islock.inputnum", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL };
static header_field_info hfi_msg_islock_input_count64 DASH_HFI_INIT =
  { "Number of inputs", "dash.islock.inputnum64", FT_UINT64, BASE_DEC, NULL, 0x0, NULL, HFILL };
static header_field_info hfi_msg_islock_inputs DASH_HFI_INIT =
  { "Inputs", "dash.islock.inputs", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL };
static header_field_info hfi_msg_islock_txid DASH_HFI_INIT =
  { "TXID", "dash.islock.txid", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL };
static header_field_info hfi_msg_islock_sig DASH_HFI_INIT =
  { "LLMQ BLS Signature", "dash.islock.blssignature", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL };

/* mnauth message: */
static header_field_info hfi_dash_msg_mnauth DASH_HFI_INIT =
  { "mnauth message", "dash.mnauth", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL };
static header_field_info hfi_msg_mnauth_proregtx DASH_HFI_INIT =
  { "ProRegTx Hash", "dash.mnauth.proregtx", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL };
static header_field_info hfi_msg_mnauth_blssignature DASH_HFI_INIT =
  { "Masternode BLS Signature", "dash.mnauth.blssignature", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL };

/* qcontrib message: */
static header_field_info hfi_dash_msg_qcontrib DASH_HFI_INIT =
  { "qcontrib message", "dash.qcontrib", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL };
static header_field_info hfi_msg_qcontrib_llmq_type DASH_HFI_INIT =
  { "LLMQ Type", "dash.qcontrib.llmqtype", FT_UINT8, BASE_DEC, VALS(llmq_type), 0x0, NULL, HFILL };
static header_field_info hfi_msg_qcontrib_quorum_hash DASH_HFI_INIT =
  { "Quorum Hash", "dash.qcontrib.quorumhash", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL };
static header_field_info hfi_msg_qcontrib_protx_hash DASH_HFI_INIT =
  { "ProRegTx Hash", "dash.qcontrib.protxhash", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL };
static header_field_info hfi_msg_qcontrib_vvec_size8 DASH_HFI_INIT =
  { "Vector Size", "dash.qcontrib.vvecsize", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL };
static header_field_info hfi_msg_qcontrib_vvec_size16 DASH_HFI_INIT =
  { "Vector Size", "dash.qcontrib.vvecsize", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL };
static header_field_info hfi_msg_qcontrib_vvec_size32 DASH_HFI_INIT =
  { "Vector Size", "dash.qcontrib.vvecsize", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL };
static header_field_info hfi_msg_qcontrib_vvec_size64 DASH_HFI_INIT =
  { "Vector Size", "dash.qcontrib.vvecsize64", FT_UINT64, BASE_DEC, NULL, 0x0, NULL, HFILL };
static header_field_info hfi_msg_qcontrib_vvec DASH_HFI_INIT =
  { "Verification Vector", "dash.qcontrib.vvec", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL };
static header_field_info hfi_msg_qcontrib_vvec_key DASH_HFI_INIT =
  { "Pubkey", "dash.qcontrib.vvec.key", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL };
static header_field_info hfi_msg_qcontrib_ephemeral_pubkey DASH_HFI_INIT =
  { "Ephemeral BLS Public Key", "dash.qcontrib.ephemeralpubkey", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL };
static header_field_info hfi_msg_qcontrib_iv DASH_HFI_INIT =
  { "IV Seed", "dash.qcontrib.iv", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL };
static header_field_info hfi_msg_qcontrib_sk_count8 DASH_HFI_INIT =
  { "Contribution count", "dash.qcontrib.skcount", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL };
static header_field_info hfi_msg_qcontrib_sk_count16 DASH_HFI_INIT =
  { "Contribution count", "dash.qcontrib.skcount", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL };
static header_field_info hfi_msg_qcontrib_sk_count32 DASH_HFI_INIT =
  { "Contribution count", "dash.qcontrib.skcount", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL };
static header_field_info hfi_msg_qcontrib_sk_count64 DASH_HFI_INIT =
  { "Contribution count", "dash.qcontrib.skcount64", FT_UINT64, BASE_DEC, NULL, 0x0, NULL, HFILL };
static header_field_info hfi_msg_qcontrib_sk_contrib DASH_HFI_INIT =
  { "Contributions", "dash.qcontrib.skcontrib", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL };
static header_field_info hfi_msg_qcontrib_sk_contrib_size DASH_HFI_INIT =
  { "Contribution Size", "dash.qcontrib.skcontrib.size", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL };
static header_field_info hfi_msg_qcontrib_sk_contrib_key DASH_HFI_INIT =
  { "Encrypted Secret Key contribution", "dash.qcontrib.skcontrib.key", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL };
static header_field_info hfi_msg_qcontrib_sig DASH_HFI_INIT =
  { "BLS signature (Operator Key)", "dash.qcontrib.sig", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL };

/* qcomplaint message */
static header_field_info hfi_dash_msg_qcomplaint DASH_HFI_INIT =
  { "qcomplaint message", "dash.qcomplaint", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL };
static header_field_info hfi_msg_qcomplaint_llmq_type DASH_HFI_INIT =
  { "LLMQ Type", "dash.qcomplaint.llmqtype", FT_UINT8, BASE_DEC, VALS(llmq_type), 0x0, NULL, HFILL };
static header_field_info hfi_msg_qcomplaint_quorum_hash DASH_HFI_INIT =
  { "Quorum Hash", "dash.qcomplaint.quorumhash", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL };
static header_field_info hfi_msg_qcomplaint_protx_hash DASH_HFI_INIT =
  { "ProRegTx Hash", "dash.qcomplaint.protxhash", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL };
static header_field_info hfi_msg_qcomplaint_badbit_size8 DASH_HFI_INIT =
  { "Bad member bitvector size", "dash.qcomplaint.badbitsize", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL };
static header_field_info hfi_msg_qcomplaint_badbit_size16 DASH_HFI_INIT =
  { "Bad member bitvector size", "dash.qcomplaint.badbitsize", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL };
static header_field_info hfi_msg_qcomplaint_badbit_size32 DASH_HFI_INIT =
  { "Bad member bitvector size", "dash.qcomplaint.badbitsize", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL };
static header_field_info hfi_msg_qcomplaint_badbit_size64 DASH_HFI_INIT =
  { "Bad member bitvector size", "dash.qcomplaint.badbitsize64", FT_UINT64, BASE_DEC, NULL, 0x0, NULL, HFILL };
static header_field_info hfi_msg_qcomplaint_badmembers DASH_HFI_INIT =
  { "Bad members", "dash.qcomplaint.badmembers", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL };
static header_field_info hfi_msg_qcomplaint_complaintbit_size8 DASH_HFI_INIT =
  { "Complaints bitvector size", "dash.qcomplaint.complaintbitsize", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL };
static header_field_info hfi_msg_qcomplaint_complaintbit_size16 DASH_HFI_INIT =
  { "Complaints bitvector size", "dash.qcomplaint.complaintbitsize", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL };
static header_field_info hfi_msg_qcomplaint_complaintbit_size32 DASH_HFI_INIT =
  { "Complaints bitvector size", "dash.qcomplaint.complaintbitsize", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL };
static header_field_info hfi_msg_qcomplaint_complaintbit_size64 DASH_HFI_INIT =
  { "Complaints bitvector size", "dash.qcomplaint.complaintbitsize64", FT_UINT64, BASE_DEC, NULL, 0x0, NULL, HFILL };
static header_field_info hfi_msg_qcomplaint_complaints DASH_HFI_INIT =
  { "Complaints", "dash.qcomplaint.complaints", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL };
static header_field_info hfi_msg_qcomplaint_sig DASH_HFI_INIT =
  { "BLS signature (Operator Key)", "dash.qcomplaint.sig", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL };

/* qjustify */
static header_field_info hfi_dash_msg_qjustify DASH_HFI_INIT =
  { "qjustify message", "dash.qjustify", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL };
static header_field_info hfi_msg_qjustify_llmq_type DASH_HFI_INIT =
  { "LLMQ Type", "dash.qjustify.llmqtype", FT_UINT8, BASE_DEC, VALS(llmq_type), 0x0, NULL, HFILL };
static header_field_info hfi_msg_qjustify_quorum_hash DASH_HFI_INIT =
  { "Quorum Hash", "dash.qjustify.quorumhash", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL };
static header_field_info hfi_msg_qjustify_protx_hash DASH_HFI_INIT =
  { "ProRegTx Hash", "dash.qjustify.protxhash", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL };
static header_field_info hfi_msg_qjustify_sk_count8 DASH_HFI_INIT =
  { "Contribution count", "dash.qjustify.skcount", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL };
static header_field_info hfi_msg_qjustify_sk_count16 DASH_HFI_INIT =
  { "Contribution count", "dash.qjustify.skcount", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL };
static header_field_info hfi_msg_qjustify_sk_count32 DASH_HFI_INIT =
  { "Contribution count", "dash.qjustify.skcount", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL };
static header_field_info hfi_msg_qjustify_sk_count64 DASH_HFI_INIT =
  { "Contribution count", "dash.qjustify.skcount64", FT_UINT64, BASE_DEC, NULL, 0x0, NULL, HFILL };
static header_field_info hfi_msg_qjustify_sk_justify DASH_HFI_INIT =
  { "Contributions", "dash.qjustify.skjustify", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL };
static header_field_info hfi_msg_qjustify_sk_justify_idx DASH_HFI_INIT =
  { "Contribution Size", "dash.qjustify.skjustify.idx", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL };
static header_field_info hfi_msg_qjustify_sk_justify_key DASH_HFI_INIT =
  { "Encrypted Secret Key contribution", "dash.qjustify.skjustify.key", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL };
static header_field_info hfi_msg_qjustify_sig DASH_HFI_INIT =
  { "BLS signature (Operator Key)", "dash.qjustify.sig", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL };

/* qpcommit */
static header_field_info hfi_dash_msg_qpcommit DASH_HFI_INIT =
  { "qpcommit message", "dash.qpcommit", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL };
static header_field_info hfi_msg_qpcommit_llmq_type DASH_HFI_INIT =
  { "LLMQ Type", "dash.qpcommit.llmqtype", FT_UINT8, BASE_DEC, VALS(llmq_type), 0x0, NULL, HFILL };
static header_field_info hfi_msg_qpcommit_quorum_hash DASH_HFI_INIT =
  { "Quorum Hash", "dash.qpcommit.quorumhash", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL };
static header_field_info hfi_msg_qpcommit_protx_hash DASH_HFI_INIT =
  { "ProRegTx Hash", "dash.qpcommit.protxhash", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL };
static header_field_info hfi_msg_qpcommit_validmember_size8 DASH_HFI_INIT =
  { "Valid member bitvector size", "dash.qpcommit.validmembersize", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL };
static header_field_info hfi_msg_qpcommit_validmember_size16 DASH_HFI_INIT =
  { "Valid member bitvector size", "dash.qpcommit.validmembersize", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL };
static header_field_info hfi_msg_qpcommit_validmember_size32 DASH_HFI_INIT =
  { "Valid member bitvector size", "dash.qpcommit.validmembersize", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL };
static header_field_info hfi_msg_qpcommit_validmember_size64 DASH_HFI_INIT =
  { "Valid member bitvector size", "dash.qpcommit.validmembersize64", FT_UINT64, BASE_DEC, NULL, 0x0, NULL, HFILL };
static header_field_info hfi_msg_qpcommit_validmembers DASH_HFI_INIT =
  { "Valid members", "dash.qpcommit.validmembers", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL };
static header_field_info hfi_msg_qpcommit_quorum_pubkey DASH_HFI_INIT =
  { "Quorum BLS Public Key", "dash.qpcommit.quorumpubkey", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL };
static header_field_info hfi_msg_qpcommit_quorum_vvec_hash DASH_HFI_INIT =
  { "Quorum Verification Vector Hash", "dash.qpcommit.quorumvvechash", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL };
static header_field_info hfi_msg_qpcommit_quorum_sig DASH_HFI_INIT =
  { "BLS Threshold signature", "dash.qpcommit.quorumsig", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL };
static header_field_info hfi_msg_qpcommit_sig DASH_HFI_INIT =
  { "BLS signature (Operator Key)", "dash.qpcommit.sig", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL };

/* qfcommit */
static header_field_info hfi_dash_msg_qfcommit DASH_HFI_INIT =
  { "qfcommit message", "dash.qfcommit", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL };
static header_field_info hfi_msg_qfcommit_version DASH_HFI_INIT =
  { "Message Version", "dash.qfcommit.version", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL };
static header_field_info hfi_msg_qfcommit_llmq_type DASH_HFI_INIT =
  { "LLMQ Type", "dash.qfcommit.llmqtype", FT_UINT8, BASE_DEC, VALS(llmq_type), 0x0, NULL, HFILL };
static header_field_info hfi_msg_qfcommit_quorum_hash DASH_HFI_INIT =
  { "Quorum Hash", "dash.qfcommit.quorumhash", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL };
static header_field_info hfi_msg_qfcommit_singers_size8 DASH_HFI_INIT =
  { "Signer bitvector size", "dash.qfcommit.singersize", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL };
static header_field_info hfi_msg_qfcommit_singers_size16 DASH_HFI_INIT =
  { "Signer bitvector size", "dash.qfcommit.singersize", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL };
static header_field_info hfi_msg_qfcommit_singers_size32 DASH_HFI_INIT =
  { "Signer bitvector size", "dash.qfcommit.singersize", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL };
static header_field_info hfi_msg_qfcommit_singers_size64 DASH_HFI_INIT =
  { "Signer bitvector size", "dash.qfcommit.singersize64", FT_UINT64, BASE_DEC, NULL, 0x0, NULL, HFILL };
static header_field_info hfi_msg_qfcommit_singers DASH_HFI_INIT =
  { "Signers", "dash.qfcommit.singers", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL };
static header_field_info hfi_msg_qfcommit_validmember_size8 DASH_HFI_INIT =
  { "Valid member bitvector size", "dash.qfcommit.validmembersize", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL };
static header_field_info hfi_msg_qfcommit_validmember_size16 DASH_HFI_INIT =
  { "Valid member bitvector size", "dash.qfcommit.validmembersize", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL };
static header_field_info hfi_msg_qfcommit_validmember_size32 DASH_HFI_INIT =
  { "Valid member bitvector size", "dash.qfcommit.validmembersize", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL };
static header_field_info hfi_msg_qfcommit_validmember_size64 DASH_HFI_INIT =
  { "Valid member bitvector size", "dash.qfcommit.validmembersize64", FT_UINT64, BASE_DEC, NULL, 0x0, NULL, HFILL };
static header_field_info hfi_msg_qfcommit_validmembers DASH_HFI_INIT =
  { "Valid members", "dash.qfcommit.validmembers", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL };
static header_field_info hfi_msg_qfcommit_quorum_pubkey DASH_HFI_INIT =
  { "Quorum BLS Public Key", "dash.qfcommit.quorumpubkey", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL };
static header_field_info hfi_msg_qfcommit_quorum_vvec_hash DASH_HFI_INIT =
  { "Quorum Verification Vector Hash", "dash.qfcommit.quorumvvechash", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL };
static header_field_info hfi_msg_qfcommit_quorum_sig DASH_HFI_INIT =
  { "Quorum BLS Recovered Threshold Sig", "dash.qfcommit.quorumsig", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL };
static header_field_info hfi_msg_qfcommit_sig DASH_HFI_INIT =
  { "Quorum Aggregate BLS Sig", "dash.qfcommit.sig", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL };

/* qbsigs */
static header_field_info hfi_dash_msg_qbsigs DASH_HFI_INIT =
  { "qbsig message", "dash.qbsigs", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL };
static header_field_info hfi_msg_qbsigs_batchcount8 DASH_HFI_INIT =
  { "Number of signature share batches", "dash.qbsigs.batchcount", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL };
static header_field_info hfi_msg_qbsigs_batchcount16 DASH_HFI_INIT =
  { "Number of signature share batches", "dash.qbsigs.batchcount", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL };
static header_field_info hfi_msg_qbsigs_batchcount32 DASH_HFI_INIT =
  { "Number of signature share batches", "dash.qbsigs.batchcount", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL };
static header_field_info hfi_msg_qbsigs_batchcount64 DASH_HFI_INIT =
  { "Number of signature share batches", "dash.qbsigs.batchcount64", FT_UINT64, BASE_DEC, NULL, 0x0, NULL, HFILL };
static header_field_info hfi_msg_qbsigs_batched_sigshares DASH_HFI_INIT =
  { "Signature share batch", "dash.qbsigs.bsigshare", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL };
static header_field_info hfi_msg_qbsigs_batched_sigshares_sessionid DASH_HFI_INIT =
  { "Session ID", "dash.qbsigs.bsigshare.id", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL };
static header_field_info hfi_msg_qbsigs_batched_sigshares_sharecount8 DASH_HFI_INIT =
  { "Share count", "dash.qbsigs.bsigshare.count", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL };
static header_field_info hfi_msg_qbsigs_batched_sigshares_sharecount16 DASH_HFI_INIT =
  { "Share count", "dash.qbsigs.bsigshare.count", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL };
static header_field_info hfi_msg_qbsigs_batched_sigshares_sharecount32 DASH_HFI_INIT =
  { "Share count", "dash.qbsigs.bsigshare.count", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL };
static header_field_info hfi_msg_qbsigs_batched_sigshares_sharecount64 DASH_HFI_INIT =
  { "Share count", "dash.qbsigs.bsigshare.count64", FT_UINT64, BASE_DEC, NULL, 0x0, NULL, HFILL };
static header_field_info hfi_msg_qbsigs_batched_sigshares_sigshares DASH_HFI_INIT =
  { "qsigsesann message", "dash.qbsigs.bsigshare.sigshare", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL };
static header_field_info hfi_msg_qbsigs_batched_sigshares_sigshares_index DASH_HFI_INIT =
  { "Index", "dash.qbsigs.bsigshare.sigshare.index", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL };
static header_field_info hfi_msg_qbsigs_batched_sigshares_sigshares_sig DASH_HFI_INIT =
  { "BLS signature share", "dash.qbsigs.bsigshare.sigshare.sig", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL };

/* qgetsigs */
static header_field_info hfi_dash_msg_qgetsigs DASH_HFI_INIT =
  { "qgetsigs message", "dash.qgetsigs", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL };
static header_field_info hfi_msg_qgetsigs_count8 DASH_HFI_INIT =
  { "Count", "dash.qgetsigs.count", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL };
static header_field_info hfi_msg_qgetsigs_count16 DASH_HFI_INIT =
  { "Count", "dash.qgetsigs.count", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL };
static header_field_info hfi_msg_qgetsigs_count32 DASH_HFI_INIT =
  { "Count", "dash.qgetsigs.count", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL };
static header_field_info hfi_msg_qgetsigs_count64 DASH_HFI_INIT =
  { "Count", "dash.qgetsigs.count64", FT_UINT64, BASE_DEC, NULL, 0x0, NULL, HFILL };
static header_field_info hfi_msg_qgetsigs_sigs DASH_HFI_INIT =
  { "Signature share request", "dash.qgetsigs.sigs", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL };
static header_field_info hfi_msg_qgetsigs_sigs_sessionid DASH_HFI_INIT =
  { "Session ID", "dash.qgetsigs.sigs.id", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL };
static header_field_info hfi_msg_qgetsigs_sigs_invsize8 DASH_HFI_INIT =
  { "Inventory size", "dash.qgetsigs.sigs.invsize", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL };
static header_field_info hfi_msg_qgetsigs_sigs_invsize16 DASH_HFI_INIT =
  { "Inventory size", "dash.qgetsigs.sigs.invsize", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL };
static header_field_info hfi_msg_qgetsigs_sigs_invsize32 DASH_HFI_INIT =
  { "Inventory size", "dash.qgetsigs.sigs.invsize", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL };
static header_field_info hfi_msg_qgetsigs_sigs_invsize64 DASH_HFI_INIT =
  { "Inventory size", "dash.qgetsigs.sigs.invsize64", FT_UINT64, BASE_DEC, NULL, 0x0, NULL, HFILL };
static header_field_info hfi_msg_qgetsigs_sigs_inv DASH_HFI_INIT =
  { "Inventory", "dash.qgetsigs.sigs.inv", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL };

/* qsendrecsigs message: */
static header_field_info hfi_dash_msg_qsendrecsigs DASH_HFI_INIT =
  { "qsendrecsigs message", "dash.qsendrecsigs", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL };
static header_field_info hfi_msg_qsendrecsigs_enable DASH_HFI_INIT =
  { "Request recovered signatures", "dash.qsendrecsigs.enable", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL };

/* qsigrec */
static header_field_info hfi_dash_msg_qsigrec DASH_HFI_INIT =
  { "qsigrec message", "dash.qsigrec", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL };
static header_field_info hfi_msg_qsigrec_llmq_type DASH_HFI_INIT =
  { "LLMQ type", "dash.qsigrec.llmqtype", FT_UINT8, BASE_DEC, VALS(llmq_type), 0x0, NULL, HFILL };
static header_field_info hfi_msg_qsigrec_quorumhash DASH_HFI_INIT =
  { "Quorum Hash", "dash.qsigrec.quorumhash", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL };
static header_field_info hfi_msg_qsigrec_id DASH_HFI_INIT =
  { "Signing Request ID", "dash.qsigrec.id", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL };
static header_field_info hfi_msg_qsigrec_msghash DASH_HFI_INIT =
  { "Message Hash", "dash.qsigrec.msghash", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL };
static header_field_info hfi_msg_qsigrec_sig DASH_HFI_INIT =
  { "LLMQ BLS Signature", "dash.qsigrec.sig", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL };

/* qsigsesann */
static header_field_info hfi_dash_msg_qsigsesann DASH_HFI_INIT =
  { "qsigsesann message", "dash.qsigsesann", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL };
static header_field_info hfi_msg_qsigsesann_count8 DASH_HFI_INIT =
  { "Count", "dash.qsigsesann.count", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL };
static header_field_info hfi_msg_qsigsesann_count16 DASH_HFI_INIT =
  { "Count", "dash.qsigsesann.count", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL };
static header_field_info hfi_msg_qsigsesann_count32 DASH_HFI_INIT =
  { "Count", "dash.qsigsesann.count", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL };
static header_field_info hfi_msg_qsigsesann_count64 DASH_HFI_INIT =
  { "Count", "dash.qsigsesann.count64", FT_UINT64, BASE_DEC, NULL, 0x0, NULL, HFILL };
static header_field_info hfi_msg_qsigsesann_sesann DASH_HFI_INIT =
  { "Session Announcement", "dash.qsigsesann.sesann", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL };
static header_field_info hfi_msg_qsigsesann_sesann_sessionid DASH_HFI_INIT =
  { "Session ID", "dash.qsigsesann.id", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL };
static header_field_info hfi_msg_qsigsesann_sesann_llmq_type DASH_HFI_INIT =
  { "LLMQ Type", "dash.qsigsesann.sesann.llmqtype", FT_UINT8, BASE_DEC, VALS(llmq_type), 0x0, NULL, HFILL };
static header_field_info hfi_msg_qsigsesann_sesann_quorum_hash DASH_HFI_INIT =
  { "Quorum Hash", "dash.qsigsesann.sesann.quorumhash", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL };
static header_field_info hfi_msg_qsigsesann_sesann_request_id DASH_HFI_INIT =
  { "Signaling Request ID", "dash.qsigsesann.sesann.requestid", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL };
static header_field_info hfi_msg_qsigsesann_sesann_message_hash DASH_HFI_INIT =
  { "Message Hash", "dash.qsigsesann.sesann.messagehash", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL };

/* qsigsinv */
static header_field_info hfi_dash_msg_qsigsinv DASH_HFI_INIT =
  { "qsigsinv message", "dash.qsigsinv", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL };
static header_field_info hfi_msg_qsigsinv_count8 DASH_HFI_INIT =
  { "Count", "dash.qsigsinv.count", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL };
static header_field_info hfi_msg_qsigsinv_count16 DASH_HFI_INIT =
  { "Count", "dash.qsigsinv.count", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL };
static header_field_info hfi_msg_qsigsinv_count32 DASH_HFI_INIT =
  { "Count", "dash.qsigsinv.count", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL };
static header_field_info hfi_msg_qsigsinv_count64 DASH_HFI_INIT =
  { "Count", "dash.qsigsinv.count64", FT_UINT64, BASE_DEC, NULL, 0x0, NULL, HFILL };
static header_field_info hfi_msg_qsigsinv_sigs DASH_HFI_INIT =
  { "Signature share request", "dash.qsigsinv.sigs", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL };
static header_field_info hfi_msg_qsigsinv_sigs_sessionid DASH_HFI_INIT =
  { "Session ID", "dash.qsigsinv.sigs.id", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL };
static header_field_info hfi_msg_qsigsinv_sigs_invsize8 DASH_HFI_INIT =
  { "Inventory size", "dash.qsigsinv.sigs.invsize", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL };
static header_field_info hfi_msg_qsigsinv_sigs_invsize16 DASH_HFI_INIT =
  { "Inventory size", "dash.qsigsinv.sigs.invsize", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL };
static header_field_info hfi_msg_qsigsinv_sigs_invsize32 DASH_HFI_INIT =
  { "Inventory size", "dash.qsigsinv.sigs.invsize", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL };
static header_field_info hfi_msg_qsigsinv_sigs_invsize64 DASH_HFI_INIT =
  { "Inventory size", "dash.qsigsinv.sigs.invsize64", FT_UINT64, BASE_DEC, NULL, 0x0, NULL, HFILL };
static header_field_info hfi_msg_qsigsinv_sigs_inv DASH_HFI_INIT =
  { "Inventory", "dash.qsigsinv.sigs.inv", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL };

static gint ett_dash = -1;
static gint ett_dash_msg = -1;
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

static expert_field ei_dash_command_unknown = EI_INIT;
static expert_field ei_dash_script_len = EI_INIT;


static gboolean dash_desegment  = TRUE;

static guint
get_dash_pdu_length(packet_info *pinfo _U_, tvbuff_t *tvb,
                       int offset, void *data _U_)
{
  guint32 length;
  length = DASH_HEADER_LENGTH;

  /* add payload length */
  length += tvb_get_letohl(tvb, offset+16);

  return length;
}

/**
 * Add signature to tree
 */
static int //proto_tree *
create_signature_tree(proto_tree *tree, tvbuff_t *tvb, header_field_info* hfi, guint32 offset)
{
  guint8 field_length = 0;

  // Sig
  field_length = tvb_get_guint8(tvb, offset);
  proto_tree_add_item(tree, &hfi_msg_field_size, tvb, offset, 1, ENC_LITTLE_ENDIAN);
  ++offset;

  proto_tree_add_item(tree, hfi, tvb, offset, field_length, ENC_NA);  // Should be 71-73 chars per documentation, but always seems to be 67
  offset += field_length; //66;

  return offset;
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
  proto_tree_add_boolean(tree, &hfi_services_getutxo, tvb, offset, 4, (guint32)services);
  proto_tree_add_boolean(tree, &hfi_services_bloom, tvb, offset, 4, (guint32)services);

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



/*
 Change hash endianness
 This should be  done using the bytes (not converting to a string), but all
 attempts at getting that to work have been unsuccesful so far
*/
static char * change_hash_endianness(tvbuff_t *tvb, guint32 offset, char *bytestring) {
  int cx;
  long b3, b2, b1, b0;
  b0 = tvb_get_letoh64(tvb, offset + 0);
  b1 = tvb_get_letoh64(tvb, offset + 8);
  b2 = tvb_get_letoh64(tvb, offset + 16);
  b3 = tvb_get_letoh64(tvb, offset + 24);

  cx = snprintf(bytestring, 128, "%016lx", b3);
  cx = cx + snprintf(bytestring + cx, 128 - cx, "%016lx", b2);
  cx = cx + snprintf(bytestring + cx, 128 - cx, "%016lx", b1);
  cx = cx + snprintf(bytestring + cx, 128 - cx, "%016lx", b0);

  return bytestring;
}

/**
 * Create a sub-tree and fill it with a COutputPoint structure
 */
static int //proto_tree *
create_coutputpoint_tree(tvbuff_t *tvb, proto_item *ti, header_field_info* hfi, guint32 offset)
{
  proto_tree *tree;
  tree = proto_item_add_subtree(ti, ett_address);

  //gint        count_length;

  /* COutPoint
   *   [32] hash    uint256
   *   [4]  n       uint32_t
   *
   */

  proto_tree *subtree;

  /* A funny script_length won't cause an exception since the field type is FT_NONE */
  ti = proto_tree_add_item(tree, hfi, tvb, offset, 36, ENC_NA);
  subtree = proto_item_add_subtree(ti, ett_tx_in_list);

  // Correct hash (little endian)
  char bytestring[128];
  change_hash_endianness(tvb, offset, bytestring);
  proto_tree_add_string(subtree, &hfi_msg_tx_in_prev_outp_hash_reversed, tvb, offset, 32, bytestring); //tvb_bytes_to_str(wmem_packet_scope(), tvb, offset, 32));
  proto_tree_add_item(subtree, &hfi_msg_tx_in_prev_outp_hash, tvb, offset, 32, ENC_NA);
  offset += 32;

  // Index
  proto_tree_add_item(subtree, &hfi_msg_tx_in_prev_outp_index, tvb, offset, 4, ENC_LITTLE_ENDIAN);
  offset += 4;

  return offset; //tree;
}

/**
 * Create a sub-tree and fill it with a CTxIn structure
 */
static int //proto_tree *
create_ctxin_tree(tvbuff_t *tvb, proto_item *ti, guint32 offset)
{
  proto_tree *tree;

  tree = proto_item_add_subtree(ti, ett_address);

  //proto_item *rti;
  gint        count_length;
  //guint64     in_count;
  //guint64     out_count;

  /* TxIn
   *   [36]  previous_output    outpoint
   *   [1+]  script length      var_int
   *   [ ?]  signature script   uchar[]
   *   [ 4]  sequence           uint32_t
   *
   */

  //gint        varint_length;
  //guint64     varint;

  proto_tree *subtree;
  proto_tree *prevtree;
  proto_item *pti;
  guint64     script_length;
  guint32     scr_len_offset;

  scr_len_offset = offset + 36;
  get_varint(tvb, scr_len_offset, &count_length, &script_length);

  /* A funny script_length won't cause an exception since the field type is FT_NONE */
  ti = proto_tree_add_item(tree, &hfi_msg_tx_in, tvb, offset,
      36 + (guint)script_length + 4, ENC_NA);
      //36 + count_length + (guint)script_length + 4, ENC_NA);
  subtree = proto_item_add_subtree(ti, ett_tx_in_list);

  /* previous output */
  pti = proto_tree_add_item(subtree, &hfi_msg_tx_in_prev_output, tvb, offset, 36, ENC_NA);
  prevtree = proto_item_add_subtree(pti, ett_tx_in_outp);

  // Correct hash (little endian)
  //proto_tree_add_debug_text(prevtree, "Debug - Hash: %016lx%016lx%016lx%016lx", tvb_get_letoh64(tvb, offset + 24), tvb_get_letoh64(tvb, offset + 16), tvb_get_letoh64(tvb, offset + 8), tvb_get_letoh64(tvb, offset + 0));

  char bytestring[128];
  change_hash_endianness(tvb, offset, bytestring);

  proto_tree_add_string(prevtree, &hfi_msg_tx_in_prev_outp_hash_reversed, tvb, offset, 32, bytestring); //tvb_bytes_to_str(wmem_packet_scope(), tvb, offset, 32));

  // Unsuccessful attempts to do using bytes
  //proto_tree_add_bytes_format(prevtree, 0, tvb, offset, 32, NULL, "Data chunk: %s", tvb_bytes_to_str(wmem_packet_scope(), tvb, offset, 32));
  //proto_tree_add_bytes(prevtree, &hfi_msg_tx_in_prev_outp_hash, tvb, offset, 32, NULL); //, "Data chunk: %s", tvb_bytes_to_str(wmem_packet_scope(), tvb, offset, 32));

  // Original code
  proto_tree_add_item(prevtree, &hfi_msg_tx_in_prev_outp_hash, tvb, offset, 32, ENC_NA);
  offset += 32;

  proto_tree_add_item(prevtree, &hfi_msg_tx_in_prev_outp_index, tvb, offset, 4, ENC_LITTLE_ENDIAN);
  offset += 4;
  /* end previous output */

  add_varint_item(subtree, tvb, offset, count_length, &hfi_msg_tx_in_script8, &hfi_msg_tx_in_script16,
                  &hfi_msg_tx_in_script32, &hfi_msg_tx_in_script64);

  offset += count_length;

//  if ((offset + script_length) > G_MAXINT) {
//    proto_tree_add_expert(tree, pinfo, &ei_dash_script_len,
//        tvb, scr_len_offset, count_length);
//    return G_MAXINT;
//  }

  proto_tree_add_item(subtree, &hfi_msg_tx_in_sig_script, tvb, offset, (guint)script_length, ENC_NA);
  offset += (guint)script_length;

  proto_tree_add_item(subtree, &hfi_msg_tx_in_seq, tvb, offset, 4, ENC_LITTLE_ENDIAN);
  offset += 4;

  return offset; //tree;
}

/**
 * Create a sub-tree and fill it with a CService structure
 */
static int //proto_tree *
create_cservice_tree(tvbuff_t *tvb, proto_item *ti, guint32 offset)
{
  proto_tree *tree;
  tree = proto_item_add_subtree(ti, ett_address);

  /* IPv6 address */
  proto_tree_add_item(tree, &hfi_address_address, tvb, offset, 16, ENC_NA);
  offset += 16;

  /* port */
  proto_tree_add_item(tree, &hfi_address_port, tvb, offset, 2, ENC_BIG_ENDIAN);
  offset += 2;

  return offset;
}

/**
 * Create a sub-tree and fill it with a Masternode Ping structure
 */
static int //proto_tree *
create_cmasternodeping_tree(tvbuff_t *tvb, proto_item *ti, guint32 offset)
{
  proto_tree *tree;
  tree = proto_item_add_subtree(ti, ett_dash_msg);

  // Add unspent output of the Masternode that signed the message (COutPoint)
  offset = create_coutputpoint_tree(tvb, ti, &hfi_msg_mnp_outpoint, offset);

  // Block Hash - Current chaintip blockhash minus 12
  proto_tree_add_item(tree, &hfi_msg_mnp_blockhash, tvb, offset, 32, ENC_NA);
  offset += 32;

  // sigTime - Signature time for this ping
  proto_tree_add_item(tree, &hfi_msg_mnp_sigtime, tvb, offset, 8, ENC_LITTLE_ENDIAN);
  offset += 8;

  // vchSig - Signature of this message by masternode (verifiable via pubKeyMasternode)
  offset = create_signature_tree(tree, tvb, &hfi_msg_mnp_vchsig, offset);

  return offset;
}

/**
 * Create a sub-tree and fill it with a CPubkey structure
 */
static int //proto_tree *
create_cpubkey_tree(proto_tree *tree, tvbuff_t *tvb, proto_item *ti, header_field_info* hfi, guint32 offset)
{
  guint8 field_length = 0;

  // Check length of key
  field_length = tvb_get_guint8(tvb, offset);

  // Add Public Key subtree
  ti   = proto_tree_add_item(tree, &hfi_dash_cpubkey, tvb, offset, field_length + 1, ENC_NA);
  tree = proto_item_add_subtree(ti, ett_dash_msg);

  // Add key length
  proto_tree_add_item(tree, &hfi_msg_field_size, tvb, offset, 1, ENC_LITTLE_ENDIAN);
  ++offset;

  // Add key type - Check key type by looking at first byte (2 or 3 - length = 33; 4, 6, or 7 - length = 65)
  proto_tree_add_item(tree, &hfi_msg_pubkey_type, tvb, offset, 1, ENC_LITTLE_ENDIAN);

  // Add key
  proto_tree_add_item(tree, hfi, tvb, offset, field_length, ENC_NA);  // 33-65 characters (depending on if compressed/uncompressed)
  offset += field_length;

  return offset;
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

#if 0
static proto_tree *
create_string(proto_tree *tree, tvbuff_t *tvb, guint32* offset)
{
  //proto_item *ti;
  gint        varint_length;
  guint64     varint;
  gint        string_length;

  /* First is the length of the following string as a varint  */
  get_varint(tvb, *offset, &varint_length, &varint);
  string_length = (gint) varint;

  //ti = proto_tree_add_item(tree, hfi, tvb, *offset, varint_length + string_length, ENC_NA);
  //subtree = proto_item_add_subtree(ti, ett_string);

  /* length */
  //add_varint_item(tree, tvb, *offset, varint_length, &hfi_string_varint_count8,
  //                &hfi_string_varint_count16, &hfi_string_varint_count32,
  //                &hfi_string_varint_count64);
  *offset += varint_length;

  /* string */
  proto_tree_add_item(tree, &hfi_string_value, tvb, *offset, string_length,
                      ENC_ASCII|ENC_NA);
  *offset += string_length;

  return tree; //subtree;
}
#endif

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

/**
 * Get quorum session id
 */
static int get_quorum_session_id(proto_tree *tree, tvbuff_t *tvb, gint offset, header_field_info *hfi) {
  guint value;
  guint count = 0;
  do {
    value = tvb_get_guint8(tvb, (offset + count++));
    if(!(value & 0x80)) {
      break;
    }
  } while(count < 4);
  proto_tree_add_item(tree, hfi, tvb, offset, count, ENC_NA);
  offset += count;
  return offset;
}

/**
 * Get quorum signature inventory
 */
static int get_quorum_sig_inventory(proto_tree *tree, tvbuff_t *tvb, gint offset, header_field_info *hfi, guint64 invSize) {
  guint value;
  guint invBytes = 0;

  value = tvb_get_guint8(tvb, offset);
  if(value == 0) { // fixed bitset
    invBytes = (invSize + 7) / 8;
    proto_tree_add_item(tree, hfi, tvb, offset, (invBytes + 1), ENC_NA);
  } else if(value == 1) { // variable bitset
    guint count = 1;
    while((offset + count)<G_MAXINT) {
      value = tvb_get_guint8(tvb, (offset + count++));
      if(value == 0) {
        proto_tree_add_item(tree, hfi, tvb, offset, count, ENC_NA);
        offset += count;
        break;
      }
    }
  } else { // malformed
    /* no actions */
  }
  return offset;
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
dissect_dash_msg_version(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void *data _U_)
{
  proto_item *ti;
  guint32     version;
  guint32     offset = 0;

  ti   = proto_tree_add_item(tree, &hfi_dash_msg_version, tvb, offset, -1, ENC_NA);
  tree = proto_item_add_subtree(ti, ett_dash_msg);

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
  if (version >= 70214)
  {
    proto_tree_add_item(tree, &hfi_msg_version_mn_challenge, tvb, offset, 32, ENC_NA);
    offset += 32;
  }

  return offset;
}

/**
 * Handler for address messages
 */
static int
dissect_dash_msg_addr(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void *data _U_)
{
  proto_item *ti;
  gint        length;
  guint64     count;
  guint32     offset = 0;

  ti   = proto_tree_add_item(tree, &hfi_dash_msg_addr, tvb, offset, -1, ENC_NA);
  tree = proto_item_add_subtree(ti, ett_dash_msg);

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
dissect_dash_msg_inv(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void *data _U_)
{
  proto_item *ti;
  gint        length;
  guint64     count;
  guint32     offset = 0;

  ti   = proto_tree_add_item(tree, &hfi_dash_msg_inv, tvb, offset, -1, ENC_NA);
  tree = proto_item_add_subtree(ti, ett_dash_msg);

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
dissect_dash_msg_getdata(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void *data _U_)
{
  proto_item *ti;
  gint        length;
  guint64     count;
  guint32     offset = 0;

  ti   = proto_tree_add_item(tree, &hfi_dash_msg_getdata, tvb, offset, -1, ENC_NA);
  tree = proto_item_add_subtree(ti, ett_dash_msg);

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
dissect_dash_msg_notfound(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void *data _U_)
{
  proto_item *ti;
  gint        length;
  guint64     count;
  guint32     offset = 0;

  ti   = proto_tree_add_item(tree, &hfi_dash_msg_notfound, tvb, offset, -1, ENC_NA);
  tree = proto_item_add_subtree(ti, ett_dash_msg);

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
dissect_dash_msg_getblocks(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void *data _U_)
{
  proto_item *ti;
  gint        length;
  guint64     count;
  guint32     offset = 0;

  ti   = proto_tree_add_item(tree, &hfi_dash_msg_getblocks, tvb, offset, -1, ENC_NA);
  tree = proto_item_add_subtree(ti, ett_dash_msg);

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
dissect_dash_msg_getheaders(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void *data _U_)
{
  proto_item *ti;
  gint        length;
  guint64     count;
  guint32     offset = 0;

  ti   = proto_tree_add_item(tree, &hfi_dash_msg_getheaders, tvb, offset, -1, ENC_NA);
  tree = proto_item_add_subtree(ti, ett_dash_msg);

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
 * Handler for qfcommit messages
 */

static int
dissect_dash_msg_qfcommit_common(tvbuff_t *tvb, guint32 offset, proto_tree *tree)
{
  proto_item *ti;
  gint        length;
  guint64     singerSize;
  guint64     validmemberSize;
  guint64     spaces;

  ti   = proto_tree_add_item(tree, &hfi_dash_msg_qfcommit, tvb, offset, -1, ENC_NA);
  tree = proto_item_add_subtree(ti, ett_dash_msg);

  proto_tree_add_item(tree, &hfi_msg_qfcommit_version, tvb, offset, 2, ENC_LITTLE_ENDIAN);
  offset += 2;

  proto_tree_add_item(tree, &hfi_msg_qfcommit_llmq_type, tvb, offset, 1, ENC_LITTLE_ENDIAN);
  offset += 1;

  proto_tree_add_item(tree, &hfi_msg_qfcommit_quorum_hash, tvb, offset, 32, ENC_NA);
  offset += 32;

  get_varint(tvb, offset, &length, &singerSize);
  add_varint_item(tree, tvb, offset, length, &hfi_msg_qfcommit_singers_size8, &hfi_msg_qfcommit_singers_size16,
                  &hfi_msg_qfcommit_singers_size32, &hfi_msg_qfcommit_singers_size64);
  offset += length;

  spaces = (singerSize + 7) / 8;
  proto_tree_add_item(tree, &hfi_msg_qfcommit_singers, tvb, offset, spaces, ENC_NA);
  offset += spaces;

  get_varint(tvb, offset, &length, &validmemberSize);
  add_varint_item(tree, tvb, offset, length, &hfi_msg_qfcommit_validmember_size8, &hfi_msg_qfcommit_validmember_size16,
                  &hfi_msg_qfcommit_validmember_size32, &hfi_msg_qfcommit_validmember_size64);
  offset += length;

  spaces = (validmemberSize + 7) / 8;
  proto_tree_add_item(tree, &hfi_msg_qfcommit_validmembers, tvb, offset, spaces, ENC_NA);
  offset += spaces;

  proto_tree_add_item(tree, &hfi_msg_qfcommit_quorum_pubkey, tvb, offset, 48, ENC_NA);
  offset += 48;

  proto_tree_add_item(tree, &hfi_msg_qfcommit_quorum_vvec_hash, tvb, offset, 32, ENC_NA);
  offset += 32;

  proto_tree_add_item(tree, &hfi_msg_qfcommit_quorum_sig, tvb, offset, 96, ENC_NA);
  offset += 96;

  proto_tree_add_item(tree, &hfi_msg_qfcommit_sig, tvb, offset, 96, ENC_NA);
  offset += 96;

  return offset;
}

/**
 * Handler for ProRegTx(special tx) messages
 */

static int
dissect_dash_msg_tx_extra_ProRegTx(tvbuff_t *tvb, header_field_info* hfi, guint32 offset, proto_tree *tree) {
  proto_item *subti;
  proto_item *subti2;
  proto_tree *subtree;
  proto_tree *subtree2;
  gint length;
  guint64 count;

  subti   = proto_tree_add_item(tree, hfi, tvb, offset, -1, ENC_NA);
  subtree = proto_item_add_subtree(subti, ett_dash_msg);

  proto_tree_add_item(subtree, &hfi_msg_tx_extra_proregtx_version, tvb, offset, 2, ENC_LITTLE_ENDIAN);
  offset += 2;
  proto_tree_add_item(subtree, &hfi_msg_tx_extra_proregtx_type, tvb, offset, 2, ENC_LITTLE_ENDIAN);
  offset += 2;
  proto_tree_add_item(subtree, &hfi_msg_tx_extra_proregtx_mode, tvb, offset, 2, ENC_LITTLE_ENDIAN);
  offset += 2;
  offset = create_coutputpoint_tree(tvb, subti, &hfi_msg_tx_extra_proregtx_collateral_outpoint, offset);
  proto_tree_add_item(subtree, &hfi_msg_tx_extra_proregtx_ipaddr, tvb, offset, 16, ENC_NA);
  offset += 16;
  proto_tree_add_item(subtree, &hfi_msg_tx_extra_proregtx_port, tvb, offset, 2, ENC_BIG_ENDIAN);
  offset += 2;
  proto_tree_add_item(subtree, &hfi_msg_tx_extra_proregtx_keyid_owner, tvb, offset, 20, ENC_NA);
  offset += 20;
  proto_tree_add_item(subtree, &hfi_msg_tx_extra_proregtx_opr_pubkey, tvb, offset, 48, ENC_NA);
  offset += 48;
  proto_tree_add_item(subtree, &hfi_msg_tx_extra_proregtx_keyid_voting, tvb, offset, 20, ENC_NA);
  offset += 20;
  proto_tree_add_item(subtree, &hfi_msg_tx_extra_proregtx_opr_reward, tvb, offset, 2, ENC_LITTLE_ENDIAN);
  offset += 2;
  subti2   = proto_tree_add_item(subtree, &hfi_msg_tx_extra_proregtx_script, tvb, offset, -1, ENC_NA);
  subtree2 = proto_item_add_subtree(subti2, ett_dash_msg);
  get_varint(tvb, offset, &length, &count);
  add_varint_item(subtree2, tvb, offset, length, &hfi_msg_tx_extra_proregtx_script_size8, &hfi_msg_tx_extra_proregtx_script_size16,
                  &hfi_msg_tx_extra_proregtx_script_size32, &hfi_msg_tx_extra_proregtx_script_size64);
  offset += length;
  proto_tree_add_item(subtree2, &hfi_msg_tx_extra_proregtx_script_data, tvb, offset, count, ENC_NA);
  offset += count;
  proto_tree_add_item(subtree, &hfi_msg_tx_extra_proregtx_inputshash, tvb, offset, 32, ENC_NA);
  offset += 32;
  get_varint(tvb, offset, &length, &count);
  add_varint_item(subtree, tvb, offset, count, &hfi_msg_tx_extra_proregtx_payloadsig_size8, &hfi_msg_tx_extra_proregtx_payloadsig_size16,
                  &hfi_msg_tx_extra_proregtx_payloadsig_size32, &hfi_msg_tx_extra_proregtx_payloadsig_size64);
  offset += length;
  proto_tree_add_item(subtree, &hfi_msg_tx_extra_proregtx_payloadsig, tvb, offset, count, ENC_NA);
  offset += count;

  return offset;
}

/**
 * Handler for ProUpServTx(special tx) messages
 */

static int
dissect_dash_msg_tx_extra_ProUpServTx(tvbuff_t *tvb, header_field_info* hfi, guint32 offset, proto_tree *tree) {
  proto_item *ti;
  gint length;
  guint64 count;

  ti   = proto_tree_add_item(tree, hfi, tvb, offset, -1, ENC_NA);
  proto_tree *subtree = proto_item_add_subtree(ti, ett_dash_msg);

  proto_tree_add_item(subtree, &hfi_msg_tx_extra_proupservtx_version, tvb, offset, 2, ENC_LITTLE_ENDIAN);
  offset += 2;
  proto_tree_add_item(subtree, &hfi_msg_tx_extra_proupservtx_protxhash, tvb, offset, 32, ENC_NA);
  offset += 32;
  proto_tree_add_item(subtree, &hfi_msg_tx_extra_proupservtx_ipaddr, tvb, offset, 16, ENC_NA);
  offset += 16;
  proto_tree_add_item(subtree, &hfi_msg_tx_extra_proupservtx_port, tvb, offset, 2, ENC_BIG_ENDIAN);
  offset += 2;
  get_varint(tvb, offset, &length, &count);
  add_varint_item(subtree, tvb, offset, length, &hfi_msg_tx_extra_proupservtx_script_size8, &hfi_msg_tx_extra_proupservtx_script_size16,
                  &hfi_msg_tx_extra_proupservtx_script_size32, &hfi_msg_tx_extra_proupservtx_script_size64);
  offset += length;
  proto_tree_add_item(subtree, &hfi_msg_tx_extra_proupservtx_script, tvb, offset, count, ENC_NA);
  offset += count;
  proto_tree_add_item(subtree, &hfi_msg_tx_extra_proupservtx_inputshash, tvb, offset, 32, ENC_NA);
  offset += 32;
  proto_tree_add_item(subtree, &hfi_msg_tx_extra_proupservtx_payloadsig, tvb, 96, count, ENC_NA);
  offset += 96;

  return offset;
}

/**
 * Handler for ProUpRegTx(special tx) messages
 */

static int
dissect_dash_msg_tx_extra_ProUpRegTx(tvbuff_t *tvb, header_field_info* hfi, guint32 offset, proto_tree *tree) {
  proto_item *subti;
  proto_item *subti2;
  proto_tree *subtree;
  proto_tree *subtree2;
  gint length;
  guint64 count;

  subti   = proto_tree_add_item(tree, hfi, tvb, offset, -1, ENC_NA);
  subtree = proto_item_add_subtree(subti, ett_dash_msg);

  proto_tree_add_item(subtree, &hfi_msg_tx_extra_proupregtx_version, tvb, offset, 2, ENC_LITTLE_ENDIAN);
  offset += 2;
  proto_tree_add_item(subtree, &hfi_msg_tx_extra_proupregtx_protxhash, tvb, offset, 32, ENC_NA);
  offset += 32;
  proto_tree_add_item(subtree, &hfi_msg_tx_extra_proupregtx_mode, tvb, offset, 2, ENC_LITTLE_ENDIAN);
  offset += 2;
  proto_tree_add_item(subtree, &hfi_msg_tx_extra_proupregtx_opr_pubkey, tvb, offset, 48, ENC_NA);
  offset += 48;
  proto_tree_add_item(subtree, &hfi_msg_tx_extra_proupregtx_keyid_voting, tvb, offset, 20, ENC_NA);
  offset += 20;
  subti2   = proto_tree_add_item(subtree, &hfi_msg_tx_extra_proupregtx_script, tvb, offset, -1, ENC_NA);
  subtree2 = proto_item_add_subtree(subti2, ett_dash_msg);
  get_varint(tvb, offset, &length, &count);
  add_varint_item(subtree2, tvb, offset, length, &hfi_msg_tx_extra_proupregtx_script_size8, &hfi_msg_tx_extra_proupregtx_script_size16,
                  &hfi_msg_tx_extra_proupregtx_script_size32, &hfi_msg_tx_extra_proupregtx_script_size64);
  offset += length;
  proto_tree_add_item(subtree2, &hfi_msg_tx_extra_proupregtx_script_data, tvb, offset, count, ENC_NA);
  offset += count;
  proto_tree_add_item(subtree, &hfi_msg_tx_extra_proupregtx_inputshash, tvb, offset, 32, ENC_NA);
  offset += 32;
  get_varint(tvb, offset, &length, &count);
  add_varint_item(subtree, tvb, offset, length, &hfi_msg_tx_extra_proupregtx_payloadsig_size8, &hfi_msg_tx_extra_proupregtx_payloadsig_size16,
                  &hfi_msg_tx_extra_proupregtx_payloadsig_size32, &hfi_msg_tx_extra_proupregtx_payloadsig_size64);
  offset += length;
  proto_tree_add_item(subtree, &hfi_msg_tx_extra_proupregtx_payloadsig, tvb, offset, count, ENC_NA);
  offset += count;

  return offset;
}

/**
 * Handler for ProUpRevTx(special tx) messages
 */

static int
dissect_dash_msg_tx_extra_ProUpRevTx(tvbuff_t *tvb, header_field_info* hfi, guint32 offset, proto_tree *tree) {
  proto_item *ti = proto_tree_add_item(tree, hfi, tvb, offset, -1, ENC_NA);
  proto_tree *subtree = proto_item_add_subtree(ti, ett_dash_msg);

  proto_tree_add_item(subtree, &hfi_msg_tx_extra_prouprevtx_version, tvb, offset, 2, ENC_LITTLE_ENDIAN);
  offset += 2;
  proto_tree_add_item(subtree, &hfi_msg_tx_extra_prouprevtx_protxhash, tvb, offset, 32, ENC_NA);
  offset += 32;
  proto_tree_add_item(subtree, &hfi_msg_tx_extra_prouprevtx_reason, tvb, offset, 2, ENC_NA);
  offset += 2;
  proto_tree_add_item(subtree, &hfi_msg_tx_extra_prouprevtx_inputshash, tvb, offset, 32, ENC_BIG_ENDIAN);
  offset += 32;
  proto_tree_add_item(subtree, &hfi_msg_tx_extra_prouprevtx_payloadsig, tvb, offset, 96, ENC_NA);
  offset += 96;

  return offset;
}

/**
 * Handler for CbTx(special tx) messages
 */

static int
dissect_dash_msg_tx_extra_CbTx(tvbuff_t *tvb, header_field_info* hfi, guint32 offset, proto_tree *tree) {
  proto_item *ti = proto_tree_add_item(tree, hfi, tvb, offset, -1, ENC_NA);
  proto_tree *subtree = proto_item_add_subtree(ti, ett_dash_msg);

  proto_tree_add_item(subtree, &hfi_msg_tx_extra_cbtx_version, tvb, offset, 2, ENC_LITTLE_ENDIAN);
  offset += 2;
  proto_tree_add_item(subtree, &hfi_msg_tx_extra_cbtx_height, tvb, offset, 4, ENC_NA);
  offset += 4;
  proto_tree_add_item(subtree, &hfi_msg_tx_extra_cbtx_merkle_mn, tvb, offset, 32, ENC_NA);
  offset += 32;
  proto_tree_add_item(subtree, &hfi_msg_tx_extra_cbtx_merkle_quorum, tvb, offset, 32, ENC_BIG_ENDIAN);
  offset += 32;

  return offset;
}

/**
 * Handler for QcTx(special tx) messages
 */

static int
dissect_dash_msg_tx_extra_QcTx(tvbuff_t *tvb, header_field_info* hfi, guint32 offset, proto_tree *tree) {
  proto_item *ti = proto_tree_add_item(tree, hfi, tvb, offset, -1, ENC_NA);
  proto_tree *subtree = proto_item_add_subtree(ti, ett_dash_msg);

  proto_tree_add_item(subtree, &hfi_msg_tx_extra_qctx_version, tvb, offset, 2, ENC_LITTLE_ENDIAN);
  offset += 2;
  proto_tree_add_item(subtree, &hfi_msg_tx_extra_qctx_height, tvb, offset, 4, ENC_NA);
  offset += 4;
  offset = dissect_dash_msg_qfcommit_common(tvb, offset, tree);

  return offset;
}

/**
 * Handler for tx message body
 */
static guint32
dissect_dash_msg_tx_common(tvbuff_t *tvb, guint32 offset, packet_info *pinfo, proto_tree *tree, guint msgnum)
{
  proto_item *rti;
  gint        count_length;
  guint64     in_count;
  guint64     out_count;
  guint16     tx_version;
  guint16     tx_type;
  guint64     extra_payload_size;
  gint        len_remaining;

  if (msgnum == 0) {
    rti  = proto_tree_add_item(tree, &hfi_dash_msg_tx, tvb, offset, -1, ENC_NA);
  } else {
    rti  = proto_tree_add_none_format(tree, &hfi_dash_msg_tx, tvb, offset, -1, "Tx message [ %4d ]", msgnum);
  }
  tree = proto_item_add_subtree(rti, ett_dash_msg);

  /* Get 2 byte version and type values */
  tx_version = tvb_get_letohs(tvb, offset+0);
  tx_type = tvb_get_letohs(tvb, offset+2);

  proto_tree_add_item(tree, &hfi_msg_tx_version, tvb, offset, 2, ENC_LITTLE_ENDIAN);
  offset += 2;
  proto_tree_add_item(tree, &hfi_msg_tx_type, tvb, offset, 2, ENC_LITTLE_ENDIAN);
  offset += 2;

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

    // Reversed endian
    char bytestring[128];
    change_hash_endianness(tvb, offset, bytestring);
    proto_tree_add_string(prevtree, &hfi_msg_tx_in_prev_outp_hash_reversed, tvb, offset, 32, bytestring);

    // Original endian
    proto_tree_add_item(prevtree, &hfi_msg_tx_in_prev_outp_hash, tvb, offset, 32, ENC_NA);
    offset += 32;

    proto_tree_add_item(prevtree, &hfi_msg_tx_in_prev_outp_index, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    /* end previous output */

    add_varint_item(subtree, tvb, offset, count_length, &hfi_msg_tx_in_script8, &hfi_msg_tx_in_script16,
                    &hfi_msg_tx_in_script32, &hfi_msg_tx_in_script64);

    offset += count_length;

    if ((offset + script_length) > G_MAXINT) {
      proto_tree_add_expert(tree, pinfo, &ei_dash_script_len,
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
      proto_tree_add_expert(tree, pinfo, &ei_dash_script_len,
          tvb, scr_len_offset, count_length);
      return G_MAXINT;
    }

    proto_tree_add_item(subtree, &hfi_msg_tx_out_script, tvb, offset, (guint)script_length, ENC_NA);
    offset += (guint)script_length;
  }

  proto_tree_add_item(tree, &hfi_msg_tx_lock_time, tvb, offset, 4, ENC_LITTLE_ENDIAN);
  offset += 4;

  /* Special Tx payload will be next (if present) */
  len_remaining = tvb_reported_length_remaining(tvb, offset);
  //proto_tree_add_debug_text(tree, "Debug - length remaining: %0d", len_remaining);

  if (len_remaining > 0 && (tx_version >= 2) && (tx_type > 0))
  {
    /* Extra Payload Size */
    get_varint(tvb, offset, &count_length, &extra_payload_size);
    add_varint_item(tree, tvb, offset, count_length, &hfi_msg_tx_extra_payload_size8, &hfi_msg_tx_extra_payload_size16,
                    &hfi_msg_tx_extra_payload_size32, &hfi_msg_tx_extra_payload_size64);
    offset += count_length;

    switch(tx_type) {
      case 1:
      offset = dissect_dash_msg_tx_extra_ProRegTx(tvb, &hfi_msg_tx_extra_proregtx, offset, tree);
      break;
      case 2:
      offset = dissect_dash_msg_tx_extra_ProUpServTx(tvb, &hfi_msg_tx_extra_proupservtx, offset, tree);
      break;
      case 3:
      offset = dissect_dash_msg_tx_extra_ProUpRegTx(tvb, &hfi_msg_tx_extra_proupregtx, offset, tree);
      break;
      case 4:
      offset = dissect_dash_msg_tx_extra_ProUpRevTx(tvb, &hfi_msg_tx_extra_prouprevtx, offset, tree);
      break;
      case 5:
      offset = dissect_dash_msg_tx_extra_CbTx(tvb, &hfi_msg_tx_extra_cbtx, offset, tree);
      break;
      case 6:
      offset = dissect_dash_msg_tx_extra_QcTx(tvb, &hfi_msg_tx_extra_qctx, offset, tree);
      break;
      default: /* malformed packet */
      break;
    }
  }

  /* needed for block nesting */
  proto_item_set_len(rti, offset);

  return offset;
}

/**
 * Handler for tx message
 */
static int
dissect_dash_msg_tx(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
  return dissect_dash_msg_tx_common(tvb, 0, pinfo, tree, 0);
}


/**
 * Handler for block messages
 */
static int
dissect_dash_msg_block(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
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

  ti   = proto_tree_add_item(tree, &hfi_dash_msg_block, tvb, offset, -1, ENC_NA);
  tree = proto_item_add_subtree(ti, ett_dash_msg);

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
    offset = dissect_dash_msg_tx_common(tvb, offset, pinfo, tree, msgnum);
  }

  return offset;
}

/**
 * Handler for headers messages
 */
static int
dissect_dash_msg_headers(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void *data _U_)
{
  proto_item *ti;
  gint        length;
  guint64     count;
  guint32     offset = 0;

  ti   = proto_tree_add_item(tree, &hfi_dash_msg_headers, tvb, offset, -1, ENC_NA);
  tree = proto_item_add_subtree(ti, ett_dash_msg);

  get_varint(tvb, offset, &length, &count);
  add_varint_item(tree, tvb, offset, length, &hfi_msg_headers_count8, &hfi_msg_headers_count16,
                  &hfi_msg_headers_count32, &hfi_msg_headers_count64);

  offset += length;

  for (; count > 0; count--)
  {
    proto_tree *subtree;
    guint64     txcount;

    subtree = proto_tree_add_subtree(tree, tvb, offset, -1, ett_dash_msg, NULL, "Header");

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
dissect_dash_msg_ping(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void *data _U_)
{
  proto_item *ti;
  guint32     offset = 0;

  ti   = proto_tree_add_item(tree, &hfi_dash_msg_ping, tvb, offset, -1, ENC_NA);
  tree = proto_item_add_subtree(ti, ett_dash_msg);

  proto_tree_add_item(tree, &hfi_msg_ping_nonce, tvb, offset, 8, ENC_LITTLE_ENDIAN);
  offset += 8;

  return offset;
}

/**
 * Handler for pong messages
 */
static int
dissect_dash_msg_pong(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void *data _U_)
{
  proto_item *ti;
  guint32     offset = 0;

  ti   = proto_tree_add_item(tree, &hfi_dash_msg_pong, tvb, offset, -1, ENC_NA);
  tree = proto_item_add_subtree(ti, ett_dash_msg);

  proto_tree_add_item(tree, &hfi_msg_pong_nonce, tvb, offset, 8, ENC_LITTLE_ENDIAN);
  offset += 8;

  return offset;
}

/**
 * Handler for reject messages
 */
static int
dissect_dash_msg_reject(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void *data _U_)
{
  proto_item *ti;
  guint32     offset = 0;

  ti   = proto_tree_add_item(tree, &hfi_dash_msg_reject, tvb, offset, -1, ENC_NA);
  tree = proto_item_add_subtree(ti, ett_dash_msg);

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
dissect_dash_msg_filterload(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void *data _U_)
{
  proto_item *ti;
  guint32     offset = 0;

  ti   = proto_tree_add_item(tree, &hfi_dash_msg_filterload, tvb, offset, -1, ENC_NA);
  tree = proto_item_add_subtree(ti, ett_dash_msg);

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
dissect_dash_msg_filteradd(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void *data _U_)
{
  proto_item *ti;
  guint32     offset = 0;

  ti   = proto_tree_add_item(tree, &hfi_dash_msg_filteradd, tvb, offset, -1, ENC_NA);
  tree = proto_item_add_subtree(ti, ett_dash_msg);

  create_data_tree(tree, &hfi_msg_filteradd_data, tvb, &offset);

  return offset;
}

/**
 * Handler for merkleblock messages
 */

static int
dissect_dash_msg_merkleblock(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void *data _U_)
{
  proto_item *ti;
  proto_item *subtree;
  gint        length;
  guint64     count;
  guint32     offset = 0;

  ti   = proto_tree_add_item(tree, &hfi_dash_msg_merkleblock, tvb, offset, -1, ENC_NA);
  tree = proto_item_add_subtree(ti, ett_dash_msg);

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

  subtree = proto_tree_add_subtree(tree, tvb, offset, -1, ett_dash_msg, NULL, "Hashes");

  add_varint_item(subtree, tvb, offset, length, &hfi_msg_merkleblock_hashes_count8, &hfi_msg_merkleblock_hashes_count16,
      &hfi_msg_merkleblock_hashes_count32, &hfi_msg_merkleblock_hashes_count64);
  offset += length;

  for (; count > 0; count--)
  {
    proto_tree_add_item(subtree, &hfi_msg_merkleblock_hashes_hash, tvb, offset, 32, ENC_NA);
    offset += 32;
  }

  get_varint(tvb, offset, &length, &count);

  subtree = proto_tree_add_subtree(tree, tvb, offset, -1, ett_dash_msg, NULL, "Flags");

  add_varint_item(subtree, tvb, offset, length, &hfi_msg_merkleblock_flags_size8, &hfi_msg_merkleblock_flags_size16,
                  &hfi_msg_merkleblock_flags_size32, &hfi_msg_merkleblock_flags_size64);
  offset += length;

  /* The cast to guint is save because dash messages are always smaller than 0x02000000 bytes. */
  proto_tree_add_item(subtree, &hfi_msg_merkleblock_flags_data, tvb, offset, (guint)count, ENC_ASCII|ENC_NA);
  offset += (guint32)count;

  return offset;
}

/**
 * Handler for blocktxn messages
 */

static int
dissect_dash_msg_blocktxn(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void *data _U_)
{
  proto_item *ti;
  gint        length;
  guint64     count;
  guint       msgnum;
  guint32     offset = 0;

  /*  blocktxn
   *    [32] blockhash    Binary blob
   *    [ ?] txn_count    var_int
   *    [ ?] txns         tx[]      Block transactions, in format of "tx" command
   */

  ti   = proto_tree_add_item(tree, &hfi_dash_msg_blocktxn, tvb, offset, -1, ENC_NA);
  tree = proto_item_add_subtree(ti, ett_dash_msg);

  proto_tree_add_item(tree, &hfi_msg_blocktxn_hash, tvb, offset, 32, ENC_NA);
  offset += 32;

  get_varint(tvb, offset, &length, &count);
  add_varint_item(tree, tvb, offset, length, &hfi_msg_blocktxn_tx_count8, &hfi_msg_blocktxn_tx_count16,
                  &hfi_msg_blocktxn_tx_count32, &hfi_msg_blocktxn_tx_count64);
  offset += length;

  msgnum = 0;
  for (; count>0 && offset<G_MAXINT; count--)
  {
    msgnum += 1;
    offset = dissect_dash_msg_tx_common(tvb, offset, pinfo, tree, msgnum);
  }

  return offset;
}

/**
 * Handler for cmpctblock messages
 */

static int
dissect_dash_msg_cmpctblock(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void *data _U_)
{
  proto_item *ti;
  gint        length;
  guint64     count;
  guint64     index;
  guint       msgnum;
  guint32     offset = 0;

  /*  cmpctblock
   *    [ 4] version              uint32_t
   *    [32] prev_block           char[32]
   *    [32] merkle_root          char[32]
   *    [ 4] timestamp            uint32_t  A unix timestamp ... (Currently limited to dates before the year 2106!)
   *    [ 4] bits                 uint32_t
   *    [ 4] nonce                uint32_t
   *    [ 8] short id's nonce     uint64_t
   *    [ ?] short id's length    compactSize
   *      [ ?] short ids            variable (6bytes intger[])
   *    [ ?] prefilled txn len    compactSize
   *      [ ?] prefilled tx index   var_int
   *      [ ?] txns                 tx[]      Block transactions, in format of "tx" command
   */
  ti   = proto_tree_add_item(tree, &hfi_dash_msg_cmpctblock, tvb, offset, -1, ENC_NA);
  tree = proto_item_add_subtree(ti, ett_dash_msg);

  proto_tree_add_item(tree, &hfi_msg_cmpctblock_version, tvb, offset,  4, ENC_LITTLE_ENDIAN);
  offset += 4;
  proto_tree_add_item(tree, &hfi_msg_cmpctblock_prev_block, tvb, offset, 32, ENC_NA);
  offset += 32;
  proto_tree_add_item(tree, &hfi_msg_cmpctblock_merkle_root, tvb, offset, 32, ENC_NA);
  offset += 32;
  proto_tree_add_item(tree, &hfi_msg_cmpctblock_time, tvb, offset,  4, ENC_TIME_TIMESPEC|ENC_LITTLE_ENDIAN);
  offset += 4;
  proto_tree_add_item(tree, &hfi_msg_cmpctblock_bits, tvb, offset,  4, ENC_LITTLE_ENDIAN);
  offset += 4;
  proto_tree_add_item(tree, &hfi_msg_cmpctblock_nonce, tvb, offset,  4, ENC_LITTLE_ENDIAN);
  offset += 4;
  proto_tree_add_item(tree, &hfi_msg_cmpctblock_shortids_nonce, tvb, offset, 8, ENC_LITTLE_ENDIAN);
  offset += 8;

  get_varint(tvb, offset, &length, &count);
  add_varint_item(tree, tvb, offset, length, &hfi_msg_cmpctblock_shortids_count8, &hfi_msg_cmpctblock_shortids_count16,
                  &hfi_msg_cmpctblock_shortids_count32, &hfi_msg_cmpctblock_shortids_count64);
  offset += length;

  for (; count > 0; count--)
  {
    proto_tree *tree_shortids;
    tree_shortids = proto_item_add_subtree(tree, ett_address);
    proto_tree *subtree;
    ti = proto_tree_add_item(tree_shortids, &hfi_msg_cmpctblock_shortids, tvb, offset, 6, ENC_NA);
    subtree = proto_item_add_subtree(ti, ett_tx_in_list);
    proto_tree_add_item(subtree, &hfi_msg_cmpctblock_shortids_id, tvb, offset, 6, ENC_NA);
    offset += 6;
  }

  get_varint(tvb, offset, &length, &count);
  add_varint_item(tree, tvb, offset, length, &hfi_msg_cmpctblock_prefilledtxn_count8, &hfi_msg_cmpctblock_prefilledtxn_count16,
                  &hfi_msg_cmpctblock_prefilledtxn_count32, &hfi_msg_cmpctblock_prefilledtxn_count64);
  offset += length;

  msgnum = 0;
  for (; count > 0; count--)
  {
    get_varint(tvb, offset, &length, &index);
    add_varint_item(tree, tvb, offset, length, &hfi_msg_cmpctblock_prefilledtx_index8, &hfi_msg_cmpctblock_prefilledtx_index16,
                    &hfi_msg_cmpctblock_prefilledtx_index32, &hfi_msg_cmpctblock_prefilledtx_index64);
    offset += length;
    msgnum += 1;
    offset = dissect_dash_msg_tx_common(tvb, offset, pinfo, tree, msgnum);
  }

  return offset;
}

/**
 * Handler for getblocktxn messages
 */

static int
dissect_dash_msg_getblocktxn(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void *data _U_)
{
  proto_item *ti;
  gint        length;
  guint64     count;
  guint64     index;
  guint32     offset = 0;

  /*  getblocktxn
   *    [32] blockhash    Binary blob
   *    [ ?] txn_count    var_int
   *    [ ?] txn_index    var_int[]
   */

  ti   = proto_tree_add_item(tree, &hfi_dash_msg_getblocktxn, tvb, offset, -1, ENC_NA);
  tree = proto_item_add_subtree(ti, ett_dash_msg);

  proto_tree_add_item(tree, &hfi_msg_getblocktxn_hash, tvb, offset, 32, ENC_NA);
  offset += 32;

  get_varint(tvb, offset, &length, &count);
  add_varint_item(tree, tvb, offset, length, &hfi_msg_getblocktxn_tx_count8, &hfi_msg_getblocktxn_tx_count16,
                  &hfi_msg_getblocktxn_tx_count32, &hfi_msg_getblocktxn_tx_count64);
  offset += length;

  for (; count>0; count--)
  {
    get_varint(tvb, offset, &length, &index);
    add_varint_item(tree, tvb, offset, length, &hfi_msg_getblocktxn_tx_index8, &hfi_msg_getblocktxn_tx_index16,
                    &hfi_msg_getblocktxn_tx_index32, &hfi_msg_getblocktxn_tx_index64);
    offset += length;
  }

  return offset;
}

/**
 * Handler for sendcmpct messages
 */

static int
dissect_dash_msg_sendcmpct(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void *data _U_)
{
  proto_item *ti;
  guint32     offset = 0;

  ti   = proto_tree_add_item(tree, &hfi_dash_msg_sendcmpct, tvb, offset, -1, ENC_NA);
  tree = proto_item_add_subtree(ti, ett_dash_msg);

  proto_tree_add_item(tree, &hfi_msg_sendcmpct_announce, tvb, offset, 1, ENC_LITTLE_ENDIAN);
  offset += 1;
  proto_tree_add_item(tree, &hfi_msg_sendcmpct_version, tvb, offset, 8, ENC_LITTLE_ENDIAN);
  offset += 8;

  return offset;
}


/**
 * Handler for unimplemented or payload-less messages
 */
static int
dissect_dash_msg_empty(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_)
{
    return tvb_captured_length(tvb);
}

static int dissect_dash_tcp_pdu(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
  proto_item   *ti;
  guint32       offset = 0;
  const guint8* command;
  dissector_handle_t command_handle;

  col_set_str(pinfo->cinfo, COL_PROTOCOL, "Dash");

  ti   = proto_tree_add_item(tree, hfi_dash, tvb, 0, -1, ENC_NA);
  tree = proto_item_add_subtree(ti, ett_dash);

  /* add basic protocol data */
  proto_tree_add_item(tree, &hfi_dash_magic,   tvb,  0,  4, ENC_BIG_ENDIAN);
  proto_tree_add_item_ret_string(tree, &hfi_dash_command, tvb,  4, 12, ENC_ASCII|ENC_NA, wmem_packet_scope(), &command);
  proto_tree_add_item(tree, &hfi_dash_length,  tvb, 16,  4, ENC_LITTLE_ENDIAN);
  proto_tree_add_checksum(tree, tvb, 20, &hfi_dash_checksum, -1, NULL, pinfo, 0, ENC_BIG_ENDIAN, PROTO_CHECKSUM_NO_FLAGS);

  offset = 24;

  command_handle = dissector_get_string_handle(dash_command_table, command);
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

    expert_add_info(pinfo, ti, &ei_dash_command_unknown);
  }

  return tvb_reported_length(tvb);
}

/**
 * Handler for dsq messages
 */
static int
dissect_dash_msg_dsq(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void *data _U_)
{
  proto_item *ti;
  guint32     offset = 0;

  ti   = proto_tree_add_item(tree, &hfi_dash_msg_dsq, tvb, offset, -1, ENC_NA);
  tree = proto_item_add_subtree(ti, ett_dash_msg);

  /*
  Denomination - Which denomination is allowed in this mixing session
  1 =  10    Dash
  2 =   1    Dash
  4 =   0.1  Dash
  8 =   0.01 Dash
  16 =   0.001 Dash
  */
  proto_tree_add_item(tree, &hfi_msg_dsq_denom, tvb, offset, 4, ENC_LITTLE_ENDIAN);
  offset += 4;

  // Add unspent output of the Masternode that signed the message (COutPoint)
  offset = create_coutputpoint_tree(tvb, ti, &hfi_msg_dsq_outpoint, offset);

  // Time - the time this DSQ was created
  proto_tree_add_item(tree, &hfi_msg_dsq_time, tvb, offset, 8, ENC_LITTLE_ENDIAN);
  offset += 8;

  // Ready - if the mixing pool is ready to be executed
  proto_tree_add_item(tree, &hfi_msg_dsq_ready, tvb, offset, 1, ENC_NA);
  offset += 1;

  // vchSig - Signature of this message by masternode (verifiable via pubKeyMasternode)
  offset = create_signature_tree(tree, tvb, &hfi_msg_dsq_vchsig, offset);

  return offset;
}

/**
 * Handler for mnp messages
 */
static int
dissect_dash_msg_mnp(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void *data _U_)
{
  proto_item *ti;
  guint32     offset = 0;

  ti   = proto_tree_add_item(tree, &hfi_dash_msg_mnp, tvb, offset, -1, ENC_NA);

  offset = create_cmasternodeping_tree(tvb, ti, offset);

  return offset;
}

/**
 * Handler for mnb messages
 */
static int
dissect_dash_msg_mnb(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void *data _U_)
{
  proto_item *ti;
  guint32     offset = 0;

  ti   = proto_tree_add_item(tree, &hfi_dash_msg_mnb, tvb, offset, -1, ENC_NA);
  tree = proto_item_add_subtree(ti, ett_dash_msg);

  // Add unspent output of the Masternode that signed the message (COutPoint)
  offset = create_coutputpoint_tree(tvb, ti, &hfi_msg_mnb_outpoint, offset);

  offset = create_cservice_tree(tvb, ti, offset);

  // Collateral Pubkey
  offset = create_cpubkey_tree(tree, tvb, ti, &hfi_msg_mnb_pubkey_collateral, offset);

  // Masternode Pubkey
  offset = create_cpubkey_tree(tree, tvb, ti, &hfi_msg_mnb_pubkey_masternode, offset);

  // Sig
  offset = create_signature_tree(tree, tvb, &hfi_msg_mnb_vchsig, offset);

  // Sig Time
  proto_tree_add_item(tree, &hfi_msg_mnb_sigtime, tvb, offset, 8, ENC_LITTLE_ENDIAN);
  offset += 8;

  // Protocol Version
  proto_tree_add_item(tree, &hfi_msg_mnb_protocol_version, tvb, offset, 4, ENC_LITTLE_ENDIAN);
  offset += 4;

  // CMasternodePing
  ti   = proto_tree_add_item(tree, &hfi_dash_msg_mnp, tvb, offset, -1, ENC_NA);
  offset = create_cmasternodeping_tree(tvb, ti, offset);

  return offset;
}

/**
 * Handler for mnw messages
 */
static int
dissect_dash_msg_mnw(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void *data _U_)
{
  proto_item *ti;
  guint32     offset = 0;

  ti   = proto_tree_add_item(tree, &hfi_dash_msg_mnw, tvb, offset, -1, ENC_NA);
  tree = proto_item_add_subtree(ti, ett_dash_msg);

  // Add unspent output of the Masternode that signed the message (COutPoint)
  offset = create_coutputpoint_tree(tvb, ti, &hfi_msg_mnw_outpoint, offset);

  // Block Height
  proto_tree_add_item(tree, &hfi_dash_msg_mnw_payheight, tvb, offset, 4, ENC_LITTLE_ENDIAN);
  offset += 4;

  // Payee address (CScript)
  gint        varint_length;
  guint64     varint;
  gint        string_length;

  /* First is the length of the following string as a varint  */
  get_varint(tvb, offset, &varint_length, &varint);
  string_length = (gint) varint;
  offset += varint_length;

  ti = proto_tree_add_item(tree, &hfi_msg_mnw_payeeaddress, tvb, offset, string_length, ENC_NA);
  offset += string_length;

  // Signature of Masternode signing message (char[])
  offset = create_signature_tree(tree, tvb, &hfi_msg_mnw_sig, offset);

  return offset;
}

/**
 * Handler for mnwb messages
 */
static int
dissect_dash_msg_mnwb(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void *data _U_)
{
  proto_item *ti;
  guint32     offset = 0;

  ti   = proto_tree_add_item(tree, &hfi_dash_msg_mnwb, tvb, offset, -1, ENC_NA);
  tree = proto_item_add_subtree(ti, ett_dash_msg);

  return offset;
}

/**
 * Handler for mnv messages
 */
static int
dissect_dash_msg_mnv(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void *data _U_)
{
  proto_item *ti;
  guint32     offset = 0;

  ti   = proto_tree_add_item(tree, &hfi_dash_msg_mnv, tvb, offset, -1, ENC_NA);
  tree = proto_item_add_subtree(ti, ett_dash_msg);

  // vin - Unspent output for the masternode which is voting (CTxIn)
  offset = create_ctxin_tree(tvb, ti, offset);

  // vin - Unspent output for the masternode which is voting (CTxIn)
  offset = create_ctxin_tree(tvb, ti, offset);

  // Add IP address/port (CService)
  offset = create_cservice_tree(tvb, ti, offset);

  // Nonce
  proto_tree_add_item(tree, &hfi_msg_mnv_nonce, tvb, offset, 4, ENC_LITTLE_ENDIAN);
  offset += 4;

  // Block Height
  proto_tree_add_item(tree, &hfi_msg_mnv_height, tvb, offset, 4, ENC_LITTLE_ENDIAN);
  offset += 4;

  // vchSig1
  offset = create_signature_tree(tree, tvb, &hfi_msg_mnv_vchsig1, offset);

  // vchSig2
  offset = create_signature_tree(tree, tvb, &hfi_msg_mnv_vchsig2, offset);

  return offset;
}

/**
 * Handler for dstx messages
 */
static int
dissect_dash_msg_dstx(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void *data _U_)
{
  proto_item *ti;
  guint32     offset = 0;

  ti   = proto_tree_add_item(tree, &hfi_dash_msg_dstx, tvb, offset, -1, ENC_NA);
  tree = proto_item_add_subtree(ti, ett_dash_msg);

  // Tx
  offset = dissect_dash_msg_tx_common(tvb, 0, pinfo, tree, 0);

  // Add unspent output of the Masternode that signed the message (COutPoint)
  offset = create_coutputpoint_tree(tvb, ti, &hfi_msg_dstx_outpoint, offset);

  // vchSig
  offset = create_signature_tree(tree, tvb, &hfi_msg_dstx_vchsig, offset);

  // sigTime - Signature time for this ping
  proto_tree_add_item(tree, &hfi_msg_dstx_sigtime, tvb, offset, 8, ENC_LITTLE_ENDIAN);
  offset += 8;

  return offset;
}

/**
 *  Handler for dssu messages (Mixing pool status update)
 */
static int
dissect_dash_msg_dssu(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void *data _U_)
{
  proto_item *ti;
  guint32     offset = 0;

  ti   = proto_tree_add_item(tree, &hfi_dash_msg_dssu, tvb, offset, -1, ENC_NA);
  tree = proto_item_add_subtree(ti, ett_dash_msg);

  proto_tree_add_item(tree, &hfi_dash_msg_dssu_session_id, tvb, offset, 4, ENC_LITTLE_ENDIAN);
  offset += 4;

  proto_tree_add_item(tree, &hfi_dash_msg_dssu_state, tvb, offset, 4, ENC_LITTLE_ENDIAN);
  offset += 4;

  proto_tree_add_item(tree, &hfi_dash_msg_dssu_entries, tvb, offset, 4, ENC_LITTLE_ENDIAN);
  offset += 4;

  proto_tree_add_item(tree, &hfi_dash_msg_dssu_status_update, tvb, offset, 4, ENC_LITTLE_ENDIAN);
  offset += 4;

  proto_tree_add_item(tree, &hfi_dash_msg_dssu_message_id, tvb, offset, 4, ENC_LITTLE_ENDIAN);
  offset += 4;

  return offset;
}

/**
 * Handler for dsa messages
 */
static int
dissect_dash_msg_dsa(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void *data _U_)
{
  proto_item *ti;
  guint32     offset = 0;

  ti   = proto_tree_add_item(tree, &hfi_dash_msg_dsa, tvb, offset, -1, ENC_NA);
  tree = proto_item_add_subtree(ti, ett_dash_msg);

  //Denomination - will be exclusively used when submitting inputs into the pool
  proto_tree_add_item(tree, &hfi_dash_msg_dsa_denom, tvb, offset, 4, ENC_LITTLE_ENDIAN);
  offset += 4;

  // Collateral Tx
  offset = dissect_dash_msg_tx_common(tvb, offset, pinfo, tree, 0);

  return offset;
}

/**
 * Handler for dsi messages
 */
static int
dissect_dash_msg_dsi(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void *data _U_)
{
  proto_item *ti;
  guint32     offset = 0;

  gint        length;
  guint64     count;
  gint        count_length;

  ti   = proto_tree_add_item(tree, &hfi_dash_msg_dsi, tvb, offset, -1, ENC_NA);
  tree = proto_item_add_subtree(ti, ett_dash_msg);

    /* TxIn[] */
  get_varint(tvb, offset, &length, &count);
  add_varint_item(tree, tvb, offset, length, &hfi_msg_tx_in_count8, &hfi_msg_tx_in_count16,
                  &hfi_msg_tx_in_count32, &hfi_msg_tx_in_count64);

  offset += length;

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

  // This needs to be redone (same logic for CTxIn used multiple places)
  for (; count > 0; count--)
  {
    proto_tree *subtree;
    proto_tree *prevtree;
    //proto_item *ti;
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

    // Reversed endian
    char bytestring[128];
    change_hash_endianness(tvb, offset, bytestring);
    proto_tree_add_string(prevtree, &hfi_msg_tx_in_prev_outp_hash_reversed, tvb, offset, 32, bytestring);

    // Original endian
    proto_tree_add_item(prevtree, &hfi_msg_tx_in_prev_outp_hash, tvb, offset, 32, ENC_NA);
    offset += 32;

    proto_tree_add_item(prevtree, &hfi_msg_tx_in_prev_outp_index, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    /* end previous output */

    add_varint_item(subtree, tvb, offset, count_length, &hfi_msg_tx_in_script8, &hfi_msg_tx_in_script16,
                    &hfi_msg_tx_in_script32, &hfi_msg_tx_in_script64);

    offset += count_length;

    if ((offset + script_length) > G_MAXINT) {
      proto_tree_add_expert(tree, pinfo, &ei_dash_script_len,
          tvb, scr_len_offset, count_length);
      return G_MAXINT;
    }

    proto_tree_add_item(subtree, &hfi_msg_tx_in_sig_script, tvb, offset, (guint)script_length, ENC_NA);
    offset += (guint)script_length;

    proto_tree_add_item(subtree, &hfi_msg_tx_in_seq, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
  }

  // Collateral Tx
  offset = dissect_dash_msg_tx_common(tvb, offset, pinfo, tree, 0);

    /* TxOut[] */
  get_varint(tvb, offset, &count_length, &count);
  add_varint_item(tree, tvb, offset, count_length, &hfi_msg_tx_out_count8, &hfi_msg_tx_out_count16,
                  &hfi_msg_tx_out_count32, &hfi_msg_tx_out_count64);

  offset += count_length;


  // This needs to be redone (same logic for CTxOut used multiple places)
  /*  TxOut
   *    [ 8] value
   *    [1+] script length [var_int]
   *    [ ?] script
   */
  for (; count > 0; count--)
  {
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
      proto_tree_add_expert(tree, pinfo, &ei_dash_script_len,
          tvb, scr_len_offset, count_length);
      return G_MAXINT;
    }

    proto_tree_add_item(subtree, &hfi_msg_tx_out_script, tvb, offset, (guint)script_length, ENC_NA);
    offset += (guint)script_length;
  }


  return offset;
}

/**
 * Handler for dsf messages
 */
static int
dissect_dash_msg_dsf(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void *data _U_)
{
  proto_item *ti;
  guint32     offset = 0;

  ti   = proto_tree_add_item(tree, &hfi_dash_msg_dsf, tvb, offset, -1, ENC_NA);
  tree = proto_item_add_subtree(ti, ett_dash_msg);

  proto_tree_add_item(tree, &hfi_dash_msg_dsf_session_id, tvb, offset, 4, ENC_LITTLE_ENDIAN);
  offset += 4;

  // Tx Final
  offset = dissect_dash_msg_tx_common(tvb, offset, pinfo, tree, 0);

  return offset;
}

/**
 * Handler for dss messages
 */
static int
dissect_dash_msg_dss(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void *data _U_)
{
  proto_item *ti;
  guint32     offset = 0;

  gint        length;
  guint64     count;
  gint        count_length;

  ti   = proto_tree_add_item(tree, &hfi_dash_msg_dss, tvb, offset, -1, ENC_NA);
  tree = proto_item_add_subtree(ti, ett_dash_msg);

    /* TxIn[] */
  get_varint(tvb, offset, &length, &count);
  add_varint_item(tree, tvb, offset, length, &hfi_msg_tx_in_count8, &hfi_msg_tx_in_count16,
                  &hfi_msg_tx_in_count32, &hfi_msg_tx_in_count64);

  offset += length;

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

  // This needs to be redone (same logic for CTxIn used multiple places)
  for (; count > 0; count--)
  {
    proto_tree *subtree;
    proto_tree *prevtree;
    //proto_item *ti;
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

    // Reversed endian
    char bytestring[128];
    change_hash_endianness(tvb, offset, bytestring);
    proto_tree_add_string(prevtree, &hfi_msg_tx_in_prev_outp_hash_reversed, tvb, offset, 32, bytestring);

    // Original endian
    proto_tree_add_item(prevtree, &hfi_msg_tx_in_prev_outp_hash, tvb, offset, 32, ENC_NA);
    offset += 32;

    proto_tree_add_item(prevtree, &hfi_msg_tx_in_prev_outp_index, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    /* end previous output */

    add_varint_item(subtree, tvb, offset, count_length, &hfi_msg_tx_in_script8, &hfi_msg_tx_in_script16,
                    &hfi_msg_tx_in_script32, &hfi_msg_tx_in_script64);

    offset += count_length;

    if ((offset + script_length) > G_MAXINT) {
      proto_tree_add_expert(tree, pinfo, &ei_dash_script_len,
          tvb, scr_len_offset, count_length);
      return G_MAXINT;
    }

    proto_tree_add_item(subtree, &hfi_msg_tx_in_sig_script, tvb, offset, (guint)script_length, ENC_NA);
    offset += (guint)script_length;

    proto_tree_add_item(subtree, &hfi_msg_tx_in_seq, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
  }

  return offset;
}

/**
 * Handler for dsc messages
 */
static int
dissect_dash_msg_dsc(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void *data _U_)
{
  proto_item *ti;
  guint32     offset = 0;

  ti   = proto_tree_add_item(tree, &hfi_dash_msg_dsc, tvb, offset, -1, ENC_NA);
  tree = proto_item_add_subtree(ti, ett_dash_msg);

  proto_tree_add_item(tree, &hfi_dash_msg_dsc_session_id, tvb, offset, 4, ENC_LITTLE_ENDIAN);
  offset += 4;

  proto_tree_add_item(tree, &hfi_dash_msg_dsc_message_id, tvb, offset, 4, ENC_LITTLE_ENDIAN);
  offset += 4;

  return offset;
}

/**
 * Handler for ix messages
 */
static int
dissect_dash_msg_ix(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void *data _U_)
{
  proto_item *ti;
  guint32     offset = 0;

  ti   = proto_tree_add_item(tree, &hfi_dash_msg_ix, tvb, offset, -1, ENC_NA);
  tree = proto_item_add_subtree(ti, ett_dash_msg);

  // Tx
  offset = dissect_dash_msg_tx_common(tvb, 0, pinfo, tree, 0);

  return offset;
}

/**
 * Handler for txlvote messages
 */
static int
dissect_dash_msg_txlvote(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void *data _U_)
{
  proto_item *ti;
  guint32     offset = 0;

  ti   = proto_tree_add_item(tree, &hfi_dash_msg_txlvote, tvb, offset, -1, ENC_NA);
  tree = proto_item_add_subtree(ti, ett_dash_msg);

  // Parent Hash
  proto_tree_add_item(tree, &hfi_msg_txlvote_txhash, tvb, offset, 32, ENC_NA);
  offset += 32;

  // Outpoint
  offset = create_coutputpoint_tree(tvb, ti, &hfi_msg_txlvote_outpoint, offset);

  // Outpoint Masternode
  offset = create_coutputpoint_tree(tvb, ti, &hfi_msg_txlvote_outpoint_masternode, offset);

  // Quorum Modifier
  proto_tree_add_item(tree, &hfi_msg_txlvote_quorumModHash, tvb, offset, 32, ENC_NA);
  offset += 32;

  // ProTx Hash
  proto_tree_add_item(tree, &hfi_msg_txlvote_proTxHash, tvb, offset, 32, ENC_NA);
  offset += 32;

  // Signature
  offset = create_signature_tree(tree, tvb, &hfi_msg_txlvote_vchsig, offset);

  return offset;
}

/**
 * Handler for govobj messages
 */
static int
dissect_dash_msg_govobj(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void *data _U_)
{
  proto_item *ti;
  guint32     offset = 0;

  ti   = proto_tree_add_item(tree, &hfi_dash_msg_govobj, tvb, offset, -1, ENC_NA);
  tree = proto_item_add_subtree(ti, ett_dash_msg);

  // Parent Hash
  proto_tree_add_item(tree, &hfi_msg_govobj_parenthash, tvb, offset, 32, ENC_NA);
  offset += 32;

  // Revision
  proto_tree_add_item(tree, &hfi_msg_govobj_revision, tvb, offset, 4, ENC_LITTLE_ENDIAN);
  offset += 4;

  // nTime - create time
  proto_tree_add_item(tree, &hfi_msg_govobj_createtime, tvb, offset, 8, ENC_LITTLE_ENDIAN);
  offset += 8;

  // Collateral Hash
  proto_tree_add_item(tree, &hfi_msg_govobj_collateralhash, tvb, offset, 32, ENC_NA);
  offset += 32;

  // strData
  create_string_tree(tree, &hfi_msg_govobj_strdata, tvb, &offset);

  // Object Type
  proto_tree_add_item(tree, &hfi_msg_govobj_object_type, tvb, offset, 4, ENC_LITTLE_ENDIAN);
  offset += 4;

  // Add unspent output of the Masternode that signed the message (COutPoint)
  offset = create_coutputpoint_tree(tvb, ti, &hfi_msg_govobj_outpoint, offset);

  // vchSig - Signature of this message by masternode (verifiable via pubKeyMasternode)
  offset = create_signature_tree(tree, tvb, &hfi_msg_govobj_vchsig, offset);

  return offset;
}

/**
 * Handler for govobjvote messages
 */
static int
dissect_dash_msg_govobjvote(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void *data _U_)
{
  proto_item *ti;
  guint32     offset = 0;

  ti   = proto_tree_add_item(tree, &hfi_dash_msg_govobjvote, tvb, offset, -1, ENC_NA);
  tree = proto_item_add_subtree(ti, ett_dash_msg);

  // Add unspent output of the Masternode that signed the message (COutPoint)
  offset = create_coutputpoint_tree(tvb, ti, &hfi_msg_govobjvote_outpoint, offset);

  // Block Hash - Current chaintip blockhash minus 12
  proto_tree_add_item(tree, &hfi_msg_govobjvote_parenthash, tvb, offset, 32, ENC_NA);
  offset += 32;

  // Vote Outcome
  proto_tree_add_item(tree, &hfi_msg_govobjvote_voteoutcome, tvb, offset, 4, ENC_LITTLE_ENDIAN);
  offset += 4;

  // Vote Signal
  proto_tree_add_item(tree, &hfi_msg_govobjvote_votesignal, tvb, offset, 4, ENC_LITTLE_ENDIAN);
  offset += 4;

  // nTime - Vote create time
  proto_tree_add_item(tree, &hfi_msg_govobjvote_createtime, tvb, offset, 8, ENC_LITTLE_ENDIAN);
  offset += 8;

  // vchSig - Signature of this message by masternode (verifiable via pubKeyMasternode)
  offset = create_signature_tree(tree, tvb, &hfi_msg_govobjvote_vchsig, offset);

  return offset;
}

/**
 * Handler for govsync message
 */
static int
dissect_dash_msg_govsync(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void *data _U_)
{
  proto_item *ti;
  guint32     offset = 0;

  ti   = proto_tree_add_item(tree, &hfi_dash_msg_govsync, tvb, offset, -1, ENC_NA);
  tree = proto_item_add_subtree(ti, ett_dash_msg);

  // Hash
  proto_tree_add_item(tree, &hfi_msg_govsync_hash, tvb, offset, 32, ENC_NA);
  offset += 32;

  // Bloom Filter
  create_data_tree(tree, &hfi_dash_msg_govsync_bloom_filter, tvb, &offset);

  // Hash function
  proto_tree_add_item(tree, &hfi_msg_filterload_nhashfunc, tvb, offset, 4, ENC_LITTLE_ENDIAN);
  offset += 4;

  // Tweak parameter
  proto_tree_add_item(tree, &hfi_msg_filterload_ntweak, tvb, offset, 4, ENC_LITTLE_ENDIAN);
  offset += 4;

  // Flags
  proto_tree_add_item(tree, &hfi_msg_filterload_nflags, tvb, offset, 1, ENC_LITTLE_ENDIAN);
  offset += 1;

  return offset;
}


/**
 * Handler for spork messages
 */
static int
dissect_dash_msg_spork(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void *data _U_)
{
  proto_item *ti;
  guint32     offset = 0;

  ti   = proto_tree_add_item(tree, &hfi_dash_msg_spork, tvb, offset, -1, ENC_NA);
  tree = proto_item_add_subtree(ti, ett_dash_msg);

  proto_tree_add_item(tree, &hfi_dash_msg_spork_id, tvb, offset, 4, ENC_LITTLE_ENDIAN);
  offset += 4;

  proto_tree_add_item(tree, &hfi_dash_msg_spork_value, tvb, offset, 8, ENC_LITTLE_ENDIAN);
  offset += 8;

  // sigTime - Signature time for this spork
  proto_tree_add_item(tree, &hfi_dash_msg_spork_sigtime, tvb, offset, 8, ENC_LITTLE_ENDIAN);
  offset += 8;

  // vchSig -
  offset = create_signature_tree(tree, tvb, &hfi_dash_msg_spork_vchsig, offset);

  return offset;
}

/**
 * Handler for dseg messages
 */
static int
dissect_dash_msg_dseg(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void *data _U_)
{
  proto_item *ti;
  guint32     offset = 0;

  ti   = proto_tree_add_item(tree, &hfi_dash_msg_dseg, tvb, offset, -1, ENC_NA);
  tree = proto_item_add_subtree(ti, ett_dash_msg);

  // Add unspent output of the Masternode that signed the message (COutPoint)
  offset = create_coutputpoint_tree(tvb, ti, &hfi_msg_dseg_outpoint, offset);

  return offset;
}

/**
 * Handler for ssc messages
 */
static int
dissect_dash_msg_ssc(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void *data _U_)
{
  proto_item *ti;
  guint32     offset = 0;

  ti   = proto_tree_add_item(tree, &hfi_dash_msg_ssc, tvb, offset, -1, ENC_NA);
  tree = proto_item_add_subtree(ti, ett_dash_msg);

  proto_tree_add_item(tree, &hfi_dash_msg_ssc_item_id, tvb, offset, 4, ENC_LITTLE_ENDIAN);
  offset += 4;

  proto_tree_add_item(tree, &hfi_dash_msg_ssc_count, tvb, offset, 4, ENC_LITTLE_ENDIAN);
  offset += 4;

  return offset;
}

/**
 * Handler for mnget messages
 */
static int
dissect_dash_msg_mnget(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void *data _U_)
{
  proto_item *ti;
  guint32     offset = 0;

  ti   = proto_tree_add_item(tree, &hfi_dash_msg_mnget, tvb, offset, -1, ENC_NA);
  tree = proto_item_add_subtree(ti, ett_dash_msg);

  // Removed in protocol version 70210
  //proto_tree_add_item(tree, &hfi_dash_msg_mnget_count32, tvb, offset, 4, ENC_LITTLE_ENDIAN);
  //offset += 4;

  return offset;
}


static int
dissect_dash(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
  col_clear(pinfo->cinfo, COL_INFO);
  tcp_dissect_pdus(tvb, pinfo, tree, dash_desegment, DASH_HEADER_LENGTH,
      get_dash_pdu_length, dissect_dash_tcp_pdu, data);

  return tvb_reported_length(tvb);
}

static gboolean
dissect_dash_heur(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
  guint32 magic_number;
  conversation_t *conversation;

  if (tvb_captured_length(tvb) < 4)
      return FALSE;

  magic_number = tvb_get_letohl(tvb, 0);
  if ((magic_number != DASH_MAIN_MAGIC_NUMBER) &&
      (magic_number != DASH_REGTEST_MAGIC_NUMBER) &&
      (magic_number != DASH_TESTNET3_MAGIC_NUMBER) &&
      (magic_number != DASH_DEVNET_MAGIC_NUMBER))
     return FALSE;

  /* Ok: This connection should always use the dash dissector */
  conversation = find_or_create_conversation(pinfo);
  conversation_set_dissector(conversation, dash_handle);

  dissect_dash(tvb, pinfo, tree, data);
  return TRUE;
}

/**
 * Handler for getmnlistd messages
 */

static int
dissect_dash_msg_getmnlistd(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void *data _U_)
{
  proto_item *ti;
  guint32     offset = 0;

  ti   = proto_tree_add_item(tree, &hfi_dash_msg_getmnlistd, tvb, offset, -1, ENC_NA);
  tree = proto_item_add_subtree(ti, ett_dash_msg);

  proto_tree_add_item(tree, &hfi_msg_getmnlistd_baseblockhash, tvb, offset, 32, ENC_NA);
  offset += 32;
  proto_tree_add_item(tree, &hfi_msg_getmnlistd_blockhash, tvb, offset, 32, ENC_NA);
  offset += 32;

  return offset;
}

/**
 * Handler for mnlistdiff messages
 */

static int
dissect_dash_msg_mnlistdiff(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void *data _U_)
{
  proto_item *ti;
  guint32     offset = 0;

  ti   = proto_tree_add_item(tree, &hfi_dash_msg_mnlistdiff, tvb, offset, -1, ENC_NA);
  tree = proto_item_add_subtree(ti, ett_dash_msg);

  return tvb_captured_length(tvb);
}

/**
 * Handler for senddsq messages
 */

static int
dissect_dash_msg_senddsq(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void *data _U_)
{
  proto_item *ti;
  guint32     offset = 0;

  ti   = proto_tree_add_item(tree, &hfi_dash_msg_senddsq, tvb, offset, -1, ENC_NA);
  tree = proto_item_add_subtree(ti, ett_dash_msg);

  proto_tree_add_item(tree, &hfi_msg_senddsq_enable, tvb, offset, 1, ENC_LITTLE_ENDIAN);
  offset += 1;

  return offset;
}

/**
 * Handler for clsig messages
 */

static int
dissect_dash_msg_clsig(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void *data _U_)
{
  proto_item *ti;
  guint32     offset = 0;

  ti   = proto_tree_add_item(tree, &hfi_dash_msg_clsig, tvb, offset, -1, ENC_NA);
  tree = proto_item_add_subtree(ti, ett_dash_msg);

  proto_tree_add_item(tree, &hfi_msg_clsig_height, tvb, offset, 4, ENC_LITTLE_ENDIAN);
  offset += 4;
  proto_tree_add_item(tree, &hfi_msg_clsig_blockhash, tvb, offset, 32, ENC_NA);
  offset += 32;
  proto_tree_add_item(tree, &hfi_msg_clsig_sig, tvb, offset, 96, ENC_NA);
  offset += 96;

  return offset;
}

/**
 * Handler for islock messages
 */

static int
dissect_dash_msg_islock(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void *data _U_)
{
  proto_item *ti;
  gint        length;
  guint64     inputnum;
  guint32     offset = 0;

  ti   = proto_tree_add_item(tree, &hfi_dash_msg_islock, tvb, offset, -1, ENC_NA);
  tree = proto_item_add_subtree(ti, ett_dash_msg);

  get_varint(tvb, offset, &length, &inputnum);
  add_varint_item(tree, tvb, offset, length, &hfi_msg_islock_input_count8, &hfi_msg_islock_input_count16,
                  &hfi_msg_islock_input_count32, &hfi_msg_islock_input_count64);
  offset += length;

  for (; inputnum > 0; inputnum--)
  {
    offset = create_coutputpoint_tree(tvb, ti, &hfi_msg_islock_inputs, offset);
  }

  proto_tree_add_item(tree, &hfi_msg_islock_txid, tvb, offset, 32, ENC_NA);
  offset += 32;
  proto_tree_add_item(tree, &hfi_msg_islock_sig, tvb, offset, 96, ENC_NA);
  offset += 96;

  return offset;
}

/**
 * Handler for mnauth messages
 */

static int
dissect_dash_msg_mnauth(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void *data _U_)
{
  proto_item *ti;
  guint32     offset = 0;

  ti   = proto_tree_add_item(tree, &hfi_dash_msg_mnauth, tvb, offset, -1, ENC_NA);
  tree = proto_item_add_subtree(ti, ett_dash_msg);

  proto_tree_add_item(tree, &hfi_msg_mnauth_proregtx, tvb, offset, 32, ENC_NA);
  offset += 32;
  proto_tree_add_item(tree, &hfi_msg_mnauth_blssignature, tvb, offset, 96, ENC_NA);
  offset += 96;

  return offset;
}

/**
 * Handler for qcontrib messages
 */

static int
dissect_dash_msg_qcontrib(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void *data _U_)
{
  proto_item *ti;
  gint        length;
  guint64     vvecSize;
  guint64     skCount;
  guint32     offset = 0;

  ti   = proto_tree_add_item(tree, &hfi_dash_msg_qcontrib, tvb, offset, -1, ENC_NA);
  tree = proto_item_add_subtree(ti, ett_dash_msg);

  proto_tree_add_item(tree, &hfi_msg_qcontrib_llmq_type, tvb, offset, 1, ENC_LITTLE_ENDIAN);
  offset += 1;

  proto_tree_add_item(tree, &hfi_msg_qcontrib_quorum_hash, tvb, offset, 32, ENC_NA);
  offset += 32;
  proto_tree_add_item(tree, &hfi_msg_qcontrib_protx_hash, tvb, offset, 32, ENC_NA);
  offset += 32;

  get_varint(tvb, offset, &length, &vvecSize);
  add_varint_item(tree, tvb, offset, length, &hfi_msg_qcontrib_vvec_size8, &hfi_msg_qcontrib_vvec_size16,
                  &hfi_msg_qcontrib_vvec_size32, &hfi_msg_qcontrib_vvec_size64);
  offset += length;

  for (; vvecSize > 0; vvecSize--)
  {
    proto_item *subti = proto_tree_add_item(tree, &hfi_msg_qcontrib_vvec, tvb, offset, 48, ENC_NA);
    proto_tree *subtree = proto_item_add_subtree(subti, ett_tx_in_list);
    // vvec
    proto_tree_add_item(subtree, &hfi_msg_qcontrib_vvec_key, tvb, offset, 48, ENC_NA);
    offset += 48;
  }

  proto_tree_add_item(tree, &hfi_msg_qcontrib_ephemeral_pubkey, tvb, offset, 48, ENC_NA);
  offset += 48;

  proto_tree_add_item(tree, &hfi_msg_qcontrib_iv, tvb, offset, 32, ENC_NA);
  offset += 32;

  get_varint(tvb, offset, &length, &skCount);
  add_varint_item(tree, tvb, offset, length, &hfi_msg_qcontrib_sk_count8, &hfi_msg_qcontrib_sk_count16,
                  &hfi_msg_qcontrib_sk_count32, &hfi_msg_qcontrib_sk_count64);
  offset += length;

  for (; skCount > 0; skCount--)
  {
    proto_item *subti = proto_tree_add_item(tree, &hfi_msg_qcontrib_sk_contrib, tvb, offset, 33, ENC_NA);
    proto_tree *subtree = proto_item_add_subtree(subti, ett_tx_in_list);

    // size
    proto_tree_add_item(subtree, &hfi_msg_qcontrib_sk_contrib_size, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset += 1;
    // secret key
    proto_tree_add_item(subtree, &hfi_msg_qcontrib_sk_contrib_key, tvb, offset, 32, ENC_NA);
    offset += 32;
  }

  proto_tree_add_item(tree, &hfi_msg_qcontrib_sig, tvb, offset, 96, ENC_NA);
  offset += 96;

  return offset;
}

/**
 * Handler for qcomplaint messages
 */

static int
dissect_dash_msg_qcomplaint(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void *data _U_)
{
  proto_item *ti;
  gint        length;
  guint64     badbitSize;
  guint64     complaintsbitSize;
  guint64     spaces;
  guint32     offset = 0;

  ti   = proto_tree_add_item(tree, &hfi_dash_msg_qcomplaint, tvb, offset, -1, ENC_NA);
  tree = proto_item_add_subtree(ti, ett_dash_msg);

  proto_tree_add_item(tree, &hfi_msg_qcomplaint_llmq_type, tvb, offset, 1, ENC_LITTLE_ENDIAN);
  offset += 1;

  proto_tree_add_item(tree, &hfi_msg_qcomplaint_quorum_hash, tvb, offset, 32, ENC_NA);
  offset += 32;
  proto_tree_add_item(tree, &hfi_msg_qcomplaint_protx_hash, tvb, offset, 32, ENC_NA);
  offset += 32;

  get_varint(tvb, offset, &length, &badbitSize);
  add_varint_item(tree, tvb, offset, length, &hfi_msg_qcomplaint_badbit_size8, &hfi_msg_qcomplaint_badbit_size16,
                  &hfi_msg_qcomplaint_badbit_size32, &hfi_msg_qcomplaint_badbit_size64);
  offset += length;

  spaces = (badbitSize + 7) / 8;
  proto_tree_add_item(tree, &hfi_msg_qcomplaint_badmembers, tvb, offset, spaces, ENC_NA);
  offset += spaces;

  get_varint(tvb, offset, &length, &complaintsbitSize);
  add_varint_item(tree, tvb, offset, length, &hfi_msg_qcomplaint_complaintbit_size8, &hfi_msg_qcomplaint_complaintbit_size16,
                  &hfi_msg_qcomplaint_complaintbit_size32, &hfi_msg_qcomplaint_complaintbit_size64);
  offset += length;

  spaces = (complaintsbitSize + 7) / 8;
  proto_tree_add_item(tree, &hfi_msg_qcomplaint_complaints, tvb, offset, spaces, ENC_NA);
  offset += spaces;

  proto_tree_add_item(tree, &hfi_msg_qcomplaint_sig, tvb, offset, 96, ENC_NA);
  offset += 96;

  return offset;
}

/**
 * Handler for qjustify messages
 */

static int
dissect_dash_msg_qjustify(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void *data _U_)
{
  proto_item *ti;
  gint        length;
  guint64     skjustifySize;
  guint32     offset = 0;

  ti   = proto_tree_add_item(tree, &hfi_dash_msg_qjustify, tvb, offset, -1, ENC_NA);
  tree = proto_item_add_subtree(ti, ett_dash_msg);

  proto_tree_add_item(tree, &hfi_msg_qjustify_llmq_type, tvb, offset, 1, ENC_LITTLE_ENDIAN);
  offset += 1;

  proto_tree_add_item(tree, &hfi_msg_qjustify_quorum_hash, tvb, offset, 32, ENC_NA);
  offset += 32;
  proto_tree_add_item(tree, &hfi_msg_qjustify_protx_hash, tvb, offset, 32, ENC_NA);
  offset += 32;

  get_varint(tvb, offset, &length, &skjustifySize);
  add_varint_item(tree, tvb, offset, length, &hfi_msg_qjustify_sk_count8, &hfi_msg_qjustify_sk_count16,
                  &hfi_msg_qjustify_sk_count32, &hfi_msg_qjustify_sk_count64);
  offset += length;

  for (; skjustifySize > 0; skjustifySize--)
  {
    proto_item *subti = proto_tree_add_item(tree, &hfi_msg_qjustify_sk_justify, tvb, offset, 36, ENC_NA);
    proto_tree *subtree = proto_item_add_subtree(subti, ett_tx_in_list);
    // size
    proto_tree_add_item(subtree, &hfi_msg_qjustify_sk_justify_idx, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    // secret key
    proto_tree_add_item(subtree, &hfi_msg_qjustify_sk_justify_key, tvb, offset, 32, ENC_NA);
    offset += 32;
  }

  proto_tree_add_item(tree, &hfi_msg_qjustify_sig, tvb, offset, 96, ENC_NA);
  offset += 96;

  return offset;
}

/**
 * Handler for qpcommit messages
 */

static int
dissect_dash_msg_qpcommit(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void *data _U_)
{
  proto_item *ti;
  gint        length;
  guint64     validmemberSize;
  guint64     spaces;
  guint32     offset = 0;

  ti   = proto_tree_add_item(tree, &hfi_dash_msg_qpcommit, tvb, offset, -1, ENC_NA);
  tree = proto_item_add_subtree(ti, ett_dash_msg);

  proto_tree_add_item(tree, &hfi_msg_qpcommit_llmq_type, tvb, offset, 1, ENC_LITTLE_ENDIAN);
  offset += 1;

  proto_tree_add_item(tree, &hfi_msg_qpcommit_quorum_hash, tvb, offset, 32, ENC_NA);
  offset += 32;
  proto_tree_add_item(tree, &hfi_msg_qpcommit_protx_hash, tvb, offset, 32, ENC_NA);
  offset += 32;

  get_varint(tvb, offset, &length, &validmemberSize);
  add_varint_item(tree, tvb, offset, length, &hfi_msg_qpcommit_validmember_size8, &hfi_msg_qpcommit_validmember_size16,
                  &hfi_msg_qpcommit_validmember_size32, &hfi_msg_qpcommit_validmember_size64);
  offset += length;

  spaces = (validmemberSize + 7) / 8;
  proto_tree_add_item(tree, &hfi_msg_qpcommit_validmembers, tvb, offset, spaces, ENC_NA);
  offset += spaces;

  proto_tree_add_item(tree, &hfi_msg_qpcommit_quorum_pubkey, tvb, offset, 48, ENC_NA);
  offset += 48;

  proto_tree_add_item(tree, &hfi_msg_qpcommit_quorum_vvec_hash, tvb, offset, 32, ENC_NA);
  offset += 32;

  proto_tree_add_item(tree, &hfi_msg_qpcommit_quorum_sig, tvb, offset, 96, ENC_NA);
  offset += 96;

  proto_tree_add_item(tree, &hfi_msg_qpcommit_sig, tvb, offset, 96, ENC_NA);
  offset += 96;

  return offset;
}

/**
 * Handler for qfcommit messages
 */

static int
dissect_dash_msg_qfcommit(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void *data _U_)
{
  return dissect_dash_msg_qfcommit_common(tvb, 0, tree);
}

/**
 * Handler for qbsigs messages
 */

static int
dissect_dash_msg_qbsigs(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void *data _U_)
{
  proto_item *ti;
  gint        length;
  guint64     batchCount;
  guint64     shareCount;
  guint32     offset = 0;

  ti   = proto_tree_add_item(tree, &hfi_dash_msg_qbsigs, tvb, offset, -1, ENC_NA);
  tree = proto_item_add_subtree(ti, ett_dash_msg);

  get_varint(tvb, offset, &length, &batchCount);
  add_varint_item(tree, tvb, offset, length, &hfi_msg_qbsigs_batchcount8, &hfi_msg_qbsigs_batchcount16,
                  &hfi_msg_qbsigs_batchcount32, &hfi_msg_qbsigs_batchcount64);
  offset += length;
  for (; batchCount > 0; batchCount--)
  {
    proto_item *subti   = proto_tree_add_item(tree, &hfi_msg_qbsigs_batched_sigshares, tvb, offset, -1, ENC_NA);
    proto_tree *subtree = proto_item_add_subtree(subti, ett_tx_in_list);
    offset = get_quorum_session_id(subtree, tvb, offset, &hfi_msg_qbsigs_batched_sigshares_sessionid);
    get_varint(tvb, offset, &length, &shareCount);
    add_varint_item(subtree, tvb, offset, length, &hfi_msg_qbsigs_batched_sigshares_sharecount8, &hfi_msg_qbsigs_batched_sigshares_sharecount16,
                    &hfi_msg_qbsigs_batched_sigshares_sharecount32, &hfi_msg_qbsigs_batched_sigshares_sharecount64);
    offset += length;
    for(; shareCount > 0; shareCount--) {
      proto_item *subti2 = proto_tree_add_item(subtree, &hfi_msg_qbsigs_batched_sigshares_sigshares, tvb, offset, 98, ENC_NA);
      proto_tree *subtree2 = proto_item_add_subtree(subti2, ett_tx_in_list);
      // index
      proto_tree_add_item(subtree2, &hfi_msg_qbsigs_batched_sigshares_sigshares_index, tvb, offset, 2, ENC_LITTLE_ENDIAN);
      offset += 2;
      // bls signature
      proto_tree_add_item(subtree2, &hfi_msg_qbsigs_batched_sigshares_sigshares_sig, tvb, offset, 96, ENC_NA);
      offset += 96;
    }
  }
  return offset;
}

/**
 * Handler for qgetsigs messages
 */

static int
dissect_dash_msg_qgetsigs(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void *data _U_)
{
  proto_item *ti;
  gint        length;
  guint64     count;
  guint64     invSize;
  guint32     offset = 0;

  ti   = proto_tree_add_item(tree, &hfi_dash_msg_qgetsigs, tvb, offset, -1, ENC_NA);
  tree = proto_item_add_subtree(ti, ett_dash_msg);

  get_varint(tvb, offset, &length, &count);
  add_varint_item(tree, tvb, offset, length, &hfi_msg_qgetsigs_count8, &hfi_msg_qgetsigs_count16,
                  &hfi_msg_qgetsigs_count32, &hfi_msg_qgetsigs_count64);
  offset += length;
  for (; count > 0; count--)
  {
    proto_item *subti   = proto_tree_add_item(tree, &hfi_msg_qgetsigs_sigs, tvb, offset, -1, ENC_NA);
    proto_tree *subtree = proto_item_add_subtree(subti, ett_tx_in_list);
    offset = get_quorum_session_id(subtree, tvb, offset, &hfi_msg_qgetsigs_sigs_sessionid);
    get_varint(tvb, offset, &length, &invSize);
    add_varint_item(subtree, tvb, offset, length, &hfi_msg_qgetsigs_sigs_invsize8, &hfi_msg_qgetsigs_sigs_invsize16,
                    &hfi_msg_qgetsigs_sigs_invsize32, &hfi_msg_qgetsigs_sigs_invsize64);
    offset += length;
    offset = get_quorum_sig_inventory(subtree, tvb, offset, &hfi_msg_qgetsigs_sigs_inv, invSize);
  }
  return offset;
}

/**
 * Handler for qsendrecsigs messages
 */

static int
dissect_dash_msg_qsendrecsigs(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void *data _U_)
{
  proto_item *ti;
  guint32     offset = 0;

  ti   = proto_tree_add_item(tree, &hfi_dash_msg_qsendrecsigs, tvb, offset, -1, ENC_NA);
  tree = proto_item_add_subtree(ti, ett_dash_msg);

  proto_tree_add_item(tree, &hfi_msg_qsendrecsigs_enable, tvb, offset, 1, ENC_LITTLE_ENDIAN);
  offset += 1;

  return offset;
}

/**
 * Handler for qsigrec messages
 */

static int
dissect_dash_msg_qsigrec(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void *data _U_)
{
  proto_item *ti;
  guint32     offset = 0;

  ti   = proto_tree_add_item(tree, &hfi_dash_msg_qsigrec, tvb, offset, -1, ENC_NA);
  tree = proto_item_add_subtree(ti, ett_dash_msg);

  proto_tree_add_item(tree, &hfi_msg_qsigrec_llmq_type, tvb, offset, 1, ENC_LITTLE_ENDIAN);
  offset += 1;
  proto_tree_add_item(tree, &hfi_msg_qsigrec_quorumhash, tvb, offset, 32, ENC_LITTLE_ENDIAN);
  offset += 32;
  proto_tree_add_item(tree, &hfi_msg_qsigrec_id, tvb, offset, 32, ENC_LITTLE_ENDIAN);
  offset += 32;
  proto_tree_add_item(tree, &hfi_msg_qsigrec_msghash, tvb, offset, 32, ENC_LITTLE_ENDIAN);
  offset += 32;
  proto_tree_add_item(tree, &hfi_msg_qsigrec_sig, tvb, offset, 96, ENC_LITTLE_ENDIAN);
  offset += 96;

  return offset;
}

/**
 * Handler for qsigsesann messages
 */
static int
dissect_dash_msg_qsigsesann(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void *data _U_)
{
  proto_item *ti;
  gint        length;
  guint64     count;
  guint32     offset = 0;

  ti   = proto_tree_add_item(tree, &hfi_dash_msg_qsigsesann, tvb, offset, -1, ENC_NA);
  tree = proto_item_add_subtree(ti, ett_dash_msg);

  get_varint(tvb, offset, &length, &count);
  add_varint_item(tree, tvb, offset, length, &hfi_msg_qsigsesann_count8, &hfi_msg_qsigsesann_count16,
                  &hfi_msg_qsigsesann_count32, &hfi_msg_qsigsesann_count64);
  offset += length;

  for (; count > 0; count--)
  {
    proto_item *subti   = proto_tree_add_item(tree, &hfi_msg_qsigsesann_sesann, tvb, offset, -1, ENC_NA);
    proto_tree *subtree = proto_item_add_subtree(subti, ett_dash_msg);
    offset = get_quorum_session_id(subtree, tvb, offset, &hfi_msg_qsigsesann_sesann_sessionid);
    proto_tree_add_item(subtree, &hfi_msg_qsigsesann_sesann_llmq_type, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset += 1;
    proto_tree_add_item(subtree, &hfi_msg_qsigsesann_sesann_quorum_hash, tvb, offset, 32, ENC_NA);
    offset += 32;
    proto_tree_add_item(subtree, &hfi_msg_qsigsesann_sesann_request_id, tvb, offset, 32, ENC_NA);
    offset += 32;
    proto_tree_add_item(subtree, &hfi_msg_qsigsesann_sesann_message_hash, tvb, offset, 32, ENC_NA);
    offset += 32;
  }
  return offset;
}

/**
 * Handler for qsigsinv messages
 */
static int
dissect_dash_msg_qsigsinv(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void *data _U_)
{
  proto_item *ti;
  gint        length;
  guint64     count;
  guint64     invSize;
  guint32     offset = 0;

  ti   = proto_tree_add_item(tree, &hfi_dash_msg_qgetsigs, tvb, offset, -1, ENC_NA);
  tree = proto_item_add_subtree(ti, ett_dash_msg);

  get_varint(tvb, offset, &length, &count);
  add_varint_item(tree, tvb, offset, length, &hfi_msg_qgetsigs_count8, &hfi_msg_qgetsigs_count16,
                  &hfi_msg_qgetsigs_count32, &hfi_msg_qgetsigs_count64);
  offset += length;
  for (; count > 0; count--)
  {
    proto_item *subti   = proto_tree_add_item(tree, &hfi_msg_qgetsigs_sigs, tvb, offset, -1, ENC_NA);
    proto_tree *subtree = proto_item_add_subtree(subti, ett_tx_in_list);
    offset = get_quorum_session_id(subtree, tvb, offset, &hfi_msg_qgetsigs_sigs_sessionid);
    get_varint(tvb, offset, &length, &invSize);
    add_varint_item(subtree, tvb, offset, length, &hfi_msg_qgetsigs_sigs_invsize8, &hfi_msg_qgetsigs_sigs_invsize16,
                    &hfi_msg_qgetsigs_sigs_invsize32, &hfi_msg_qgetsigs_sigs_invsize64);
    offset += length;
    offset = get_quorum_sig_inventory(subtree, tvb, offset, &hfi_msg_qgetsigs_sigs_inv, invSize);
  }
  return offset;
}

void
proto_register_dash(void)
{
#ifndef HAVE_HFI_SECTION_INIT
  static header_field_info *hfi[] = {
    &hfi_dash_magic,
    &hfi_dash_command,
    &hfi_dash_length,
    &hfi_dash_checksum,

    /* Generic fields */
    &hfi_msg_field_size,
    &hfi_msg_pubkey_type,
    &hfi_msg_pubkey_hash,

    &hfi_dash_cpubkey,
    &hfi_dash_coutpoint,

    /* version message */
    &hfi_dash_msg_version,
    &hfi_msg_version_version,
    &hfi_msg_version_services,
    &hfi_msg_version_addr_me,
    &hfi_msg_version_addr_you,
    &hfi_msg_version_timestamp,
    &hfi_msg_version_nonce,
    &hfi_msg_version_user_agent,
    &hfi_msg_version_start_height,
    &hfi_msg_version_relay,
    &hfi_msg_version_mn_challenge,

    /* addr message */
    &hfi_msg_addr_count8,
    &hfi_msg_addr_count16,
    &hfi_msg_addr_count32,
    &hfi_msg_addr_count64,
    &hfi_dash_msg_addr,
    &hfi_msg_addr_address,
    &hfi_msg_addr_timestamp,

    /* inv message */
    &hfi_msg_inv_count8,
    &hfi_msg_inv_count16,
    &hfi_msg_inv_count32,
    &hfi_msg_inv_count64,
    &hfi_dash_msg_inv,
    &hfi_msg_inv_type,
    &hfi_msg_inv_hash,

    /* getdata message */
    &hfi_msg_getdata_count8,
    &hfi_msg_getdata_count16,
    &hfi_msg_getdata_count32,
    &hfi_msg_getdata_count64,
    &hfi_dash_msg_getdata,
    &hfi_msg_getdata_type,
    &hfi_msg_getdata_hash,

    /* notfound message */
    &hfi_msg_notfound_count8,
    &hfi_msg_notfound_count16,
    &hfi_msg_notfound_count32,
    &hfi_msg_notfound_count64,
    &hfi_dash_msg_notfound,
    &hfi_msg_notfound_type,
    &hfi_msg_notfound_hash,

    /* getblocks message */
    &hfi_msg_getblocks_count8,
    &hfi_msg_getblocks_count16,
    &hfi_msg_getblocks_count32,
    &hfi_msg_getblocks_count64,
    &hfi_dash_msg_getblocks,
    &hfi_msg_getblocks_start,
    &hfi_msg_getblocks_stop,

    /* getheaders message */
    &hfi_msg_getheaders_count8,
    &hfi_msg_getheaders_count16,
    &hfi_msg_getheaders_count32,
    &hfi_msg_getheaders_count64,
    &hfi_dash_msg_getheaders,
#if 0
    &hfi_msg_getheaders_version,
#endif
    &hfi_msg_getheaders_start,
    &hfi_msg_getheaders_stop,

    /* tx message */
    &hfi_dash_msg_tx,
    &hfi_msg_tx_version,
    &hfi_msg_tx_type,

    /* tx message - input */
    &hfi_msg_tx_in_count8,
    &hfi_msg_tx_in_count16,
    &hfi_msg_tx_in_count32,
    &hfi_msg_tx_in_count64,

    &hfi_msg_tx_in,
    &hfi_msg_tx_in_prev_output,

    &hfi_msg_tx_in_prev_outp_hash,
    &hfi_msg_tx_in_prev_outp_hash_reversed,
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
    &hfi_msg_tx_extra_payload_size8,
    &hfi_msg_tx_extra_payload_size16,
    &hfi_msg_tx_extra_payload_size32,
    &hfi_msg_tx_extra_payload_size64,
    &hfi_msg_tx_extra_payload,

  /* extra-payload: ProRegTx */
    &hfi_msg_tx_extra_proregtx,
    &hfi_msg_tx_extra_proregtx_version,
    &hfi_msg_tx_extra_proregtx_type,
    &hfi_msg_tx_extra_proregtx_mode,
    &hfi_msg_tx_extra_proregtx_collateral_outpoint,
    &hfi_msg_tx_extra_proregtx_ipaddr,
    &hfi_msg_tx_extra_proregtx_port,
    &hfi_msg_tx_extra_proregtx_keyid_owner,
    &hfi_msg_tx_extra_proregtx_opr_pubkey,
    &hfi_msg_tx_extra_proregtx_keyid_voting,
    &hfi_msg_tx_extra_proregtx_opr_reward,
    &hfi_msg_tx_extra_proregtx_script,
    &hfi_msg_tx_extra_proregtx_script_size8,
    &hfi_msg_tx_extra_proregtx_script_size16,
    &hfi_msg_tx_extra_proregtx_script_size32,
    &hfi_msg_tx_extra_proregtx_script_size64,
    &hfi_msg_tx_extra_proregtx_script_data,
    &hfi_msg_tx_extra_proregtx_inputshash,
    &hfi_msg_tx_extra_proregtx_payloadsig_size8,
    &hfi_msg_tx_extra_proregtx_payloadsig_size16,
    &hfi_msg_tx_extra_proregtx_payloadsig_size32,
    &hfi_msg_tx_extra_proregtx_payloadsig_size64,
    &hfi_msg_tx_extra_proregtx_payloadsig,

  /* extra-payload: ProUpServTx */
    &hfi_msg_tx_extra_proupservtx,
    &hfi_msg_tx_extra_proupservtx_version,
    &hfi_msg_tx_extra_proupservtx_protxhash,
    &hfi_msg_tx_extra_proupservtx_ipaddr,
    &hfi_msg_tx_extra_proupservtx_port,
    &hfi_msg_tx_extra_proupservtx_script_size8,
    &hfi_msg_tx_extra_proupservtx_script_size16,
    &hfi_msg_tx_extra_proupservtx_script_size32,
    &hfi_msg_tx_extra_proupservtx_script_size64,
    &hfi_msg_tx_extra_proupservtx_script,
    &hfi_msg_tx_extra_proupservtx_inputshash,
    &hfi_msg_tx_extra_proupservtx_payloadsig,

  /* extra-payload: ProUpRegTx */
    &hfi_msg_tx_extra_proupregtx,
    &hfi_msg_tx_extra_proupregtx_version,
    &hfi_msg_tx_extra_proupregtx_protxhash,
    &hfi_msg_tx_extra_proupregtx_mode,
    &hfi_msg_tx_extra_proupregtx_opr_pubkey,
    &hfi_msg_tx_extra_proupregtx_keyid_voting,
    &hfi_msg_tx_extra_proupregtx_script,
    &hfi_msg_tx_extra_proupregtx_script_size8,
    &hfi_msg_tx_extra_proupregtx_script_size16,
    &hfi_msg_tx_extra_proupregtx_script_size32,
    &hfi_msg_tx_extra_proupregtx_script_size64,
    &hfi_msg_tx_extra_proupregtx_script_data,
    &hfi_msg_tx_extra_proupregtx_inputshash,
    &hfi_msg_tx_extra_proupregtx_payloadsig_size8,
    &hfi_msg_tx_extra_proupregtx_payloadsig_size16,
    &hfi_msg_tx_extra_proupregtx_payloadsig_size32,
    &hfi_msg_tx_extra_proupregtx_payloadsig_size64,
    &hfi_msg_tx_extra_proupregtx_payloadsig,

  /* extra-payload: ProUpRevTx */
    &hfi_msg_tx_extra_prouprevtx,
    &hfi_msg_tx_extra_prouprevtx_version,
    &hfi_msg_tx_extra_prouprevtx_protxhash,
    &hfi_msg_tx_extra_prouprevtx_reason,
    &hfi_msg_tx_extra_prouprevtx_inputshash,
    &hfi_msg_tx_extra_prouprevtx_payloadsig,

  /* extra-payload: CbTx */
    &hfi_msg_tx_extra_cbtx,
    &hfi_msg_tx_extra_cbtx_version,
    &hfi_msg_tx_extra_cbtx_height,
    &hfi_msg_tx_extra_cbtx_merkle_mn,
    &hfi_msg_tx_extra_cbtx_merkle_quorum,

  /* extra-payload: QcTx */
    &hfi_msg_tx_extra_qctx,
    &hfi_msg_tx_extra_qctx_version,
    &hfi_msg_tx_extra_qctx_height,

    /* block message */
    &hfi_msg_block_transactions8,
    &hfi_msg_block_transactions16,
    &hfi_msg_block_transactions32,
    &hfi_msg_block_transactions64,
    &hfi_dash_msg_block,
    &hfi_msg_block_version,
    &hfi_msg_block_prev_block,
    &hfi_msg_block_merkle_root,
    &hfi_msg_block_time,
    &hfi_msg_block_bits,
    &hfi_msg_block_nonce,

    /* headers message */
    &hfi_dash_msg_headers,
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
    &hfi_dash_msg_ping,
    &hfi_msg_ping_nonce,

    /* pong message */
    &hfi_dash_msg_pong,
    &hfi_msg_pong_nonce,

    /* reject message */
    &hfi_dash_msg_reject,
    &hfi_msg_reject_ccode,
    &hfi_msg_reject_message,
    &hfi_msg_reject_reason,
    &hfi_msg_reject_data,

    /* filterload message */
    &hfi_dash_msg_filterload,
    &hfi_msg_filterload_filter,
    &hfi_msg_filterload_nflags,
    &hfi_msg_filterload_nhashfunc,
    &hfi_msg_filterload_ntweak,

    /* filteradd message */
    &hfi_dash_msg_filteradd,
    &hfi_msg_filteradd_data,

    /* merkleblock message */
    &hfi_dash_msg_merkleblock,
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
    &hfi_services_getutxo,
    &hfi_services_bloom,

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

    /* mnp message */
    &hfi_dash_msg_mnp,
    &hfi_msg_mnp_outpoint,
    &hfi_msg_mnp_blockhash,
    &hfi_msg_mnp_sigtime,
    &hfi_msg_mnp_vchsig,

    /* mnb message */
    &hfi_dash_msg_mnb,
    &hfi_msg_mnb_outpoint,
    &hfi_msg_mnb_pubkey_collateral,
    &hfi_msg_mnb_pubkey_masternode,
    &hfi_msg_mnb_vchsig,
    &hfi_msg_mnb_sigtime,
    &hfi_msg_mnb_protocol_version,

    /* mnw message */
    &hfi_dash_msg_mnw,
    &hfi_msg_mnw_outpoint,
    &hfi_dash_msg_mnw_payheight,
    &hfi_msg_mnw_payeeaddress,
    &hfi_msg_mnw_sig,

    /* mnwb message */
    &hfi_dash_msg_mnwb,

    /* mnv message */
    &hfi_dash_msg_mnv,
    &hfi_msg_mnv_outpoint1,
    &hfi_msg_mnv_outpoint2,
    &hfi_msg_mnv_nonce,
    &hfi_msg_mnv_height,
    &hfi_msg_mnv_vchsig1,
    &hfi_msg_mnv_vchsig2,

    /* dstx message */
    &hfi_dash_msg_dstx,
    &hfi_msg_dstx_outpoint,
    &hfi_msg_dstx_vchsig,
    &hfi_msg_dstx_sigtime,

    /* dssu message */
    &hfi_dash_msg_dssu,
    &hfi_dash_msg_dssu_session_id,
    &hfi_dash_msg_dssu_state,
    &hfi_dash_msg_dssu_entries,
    &hfi_dash_msg_dssu_status_update,
    &hfi_dash_msg_dssu_message_id,

    /* dsq message */
    &hfi_dash_msg_dsq,
    &hfi_msg_dsq_denom,
    &hfi_msg_dsq_outpoint,
    &hfi_msg_dsq_vin_prev_outp_hash,
    &hfi_msg_dsq_vin_prev_outp_index,
    &hfi_msg_dsq_vin_seq,
    &hfi_msg_dsq_time,
    &hfi_msg_dsq_ready,
    &hfi_msg_dsq_vchsig,

    /* dsa message */
    &hfi_dash_msg_dsa,
    &hfi_dash_msg_dsa_denom,

    /* dsi message */
    &hfi_dash_msg_dsi,

    /* dsf message */
    &hfi_dash_msg_dsf,
    &hfi_dash_msg_dsf_session_id,

    /* dss message */
    &hfi_dash_msg_dss,

    /* dsc message */
    &hfi_dash_msg_dsc,
    &hfi_dash_msg_dsc_session_id,
    &hfi_dash_msg_dsc_message_id,

    /* ix message */
    &hfi_dash_msg_ix,

    /* txlvote message */
    &hfi_dash_msg_txlvote,
    &hfi_msg_txlvote_txhash,
    &hfi_msg_txlvote_outpoint,
    &hfi_msg_txlvote_outpoint_masternode,
    &hfi_msg_txlvote_quorumModHash,
    &hfi_msg_txlvote_proTxHash,
    &hfi_msg_txlvote_vchsig,

    /* govobj message */
    &hfi_dash_msg_govobj,
    &hfi_msg_govobj_parenthash,
    &hfi_msg_govobj_revision,
    &hfi_msg_govobj_createtime,
    &hfi_msg_govobj_collateralhash,
    &hfi_msg_govobj_strdata,
    &hfi_msg_govobj_object_type,
    &hfi_msg_govobj_outpoint,
    &hfi_msg_govobj_vchsig,

    /* govobjvote message */
    &hfi_dash_msg_govobjvote,
    &hfi_msg_govobjvote_outpoint,
    &hfi_msg_govobjvote_parenthash,
    &hfi_msg_govobjvote_voteoutcome,
    &hfi_msg_govobjvote_votesignal,
    &hfi_msg_govobjvote_createtime,
    &hfi_msg_govobjvote_vchsig,

    /* govsync message */
    &hfi_dash_msg_govsync,
    &hfi_msg_govsync_hash,
    &hfi_dash_msg_govsync_bloom_filter,

    /* spork message */
    &hfi_dash_msg_spork,
    &hfi_dash_msg_spork_id,
    &hfi_dash_msg_spork_value,
    &hfi_dash_msg_spork_sigtime,
    &hfi_dash_msg_spork_vchsig,

    /* dseg message */
    &hfi_dash_msg_dseg,
    &hfi_msg_dseg_outpoint,

    /* ssc message */
    &hfi_dash_msg_ssc,
    &hfi_dash_msg_ssc_item_id,
    &hfi_dash_msg_ssc_count,

    /* mnget message */
    &hfi_dash_msg_mnget,
    //&hfi_dash_msg_mnget_count32, //REMOVED in protocol version 70210

    /* blocktxn message */
    &hfi_dash_msg_blocktxn,
    &hfi_msg_blocktxn_hash,
    &hfi_msg_blocktxn_tx_count8,
    &hfi_msg_blocktxn_tx_count16,
    &hfi_msg_blocktxn_tx_count32,
    &hfi_msg_blocktxn_tx_count64,

    /* cmpctblock message */
    &hfi_dash_msg_cmpctblock,
    &hfi_msg_cmpctblock_version,
    &hfi_msg_cmpctblock_prev_block,
    &hfi_msg_cmpctblock_merkle_root,
    &hfi_msg_cmpctblock_time,
    &hfi_msg_cmpctblock_bits,
    &hfi_msg_cmpctblock_nonce,
    &hfi_msg_cmpctblock_shortids_nonce,
    &hfi_msg_cmpctblock_shortids_count8,
    &hfi_msg_cmpctblock_shortids_count16,
    &hfi_msg_cmpctblock_shortids_count32,
    &hfi_msg_cmpctblock_shortids_count64,
    &hfi_msg_cmpctblock_shortids,
    &hfi_msg_cmpctblock_shortids_id,
    &hfi_msg_cmpctblock_prefilledtxn_count8,
    &hfi_msg_cmpctblock_prefilledtxn_count16,
    &hfi_msg_cmpctblock_prefilledtxn_count32,
    &hfi_msg_cmpctblock_prefilledtxn_count64,
    &hfi_msg_cmpctblock_prefilledtx,
    &hfi_msg_cmpctblock_prefilledtx_index8,
    &hfi_msg_cmpctblock_prefilledtx_index16,
    &hfi_msg_cmpctblock_prefilledtx_index32,
    &hfi_msg_cmpctblock_prefilledtx_index64,

    /* getblocktxn message */
    &hfi_dash_msg_getblocktxn,
    &hfi_msg_getblocktxn_hash,
    &hfi_msg_getblocktxn_tx_count8,
    &hfi_msg_getblocktxn_tx_count16,
    &hfi_msg_getblocktxn_tx_count32,
    &hfi_msg_getblocktxn_tx_count64,
    &hfi_msg_getblocktxn_tx_index8,
    &hfi_msg_getblocktxn_tx_index16,
    &hfi_msg_getblocktxn_tx_index32,
    &hfi_msg_getblocktxn_tx_index64,

    /* sendcmpct message */
    &hfi_dash_msg_sendcmpct,
    &hfi_msg_sendcmpct_announce,
    &hfi_msg_sendcmpct_version,

    /* Special transactions */
    &hfi_msg_specialtx_payload_version,

    /* SubTx Register */
    &hfi_dash_msg_subtx,
    &hfi_dash_msg_subtx_username,

	/* getmnlisted: */
    &hfi_dash_msg_getmnlistd,
    &hfi_msg_getmnlistd_baseblockhash,
    &hfi_msg_getmnlistd_blockhash,

  /* mnlistdiff: */
    &hfi_dash_msg_mnlistdiff,

  /* senddsq message: */
    &hfi_dash_msg_senddsq,
    &hfi_msg_senddsq_enable,

  /* clsig messsage: */
    &hfi_dash_msg_clsig,
    &hfi_msg_clsig_height,
    &hfi_msg_clsig_blockhash,
    &hfi_msg_clsig_sig,

  /* islock message: */
    &hfi_dash_msg_islock,
    &hfi_msg_islock_input_count8,
    &hfi_msg_islock_input_count16,
    &hfi_msg_islock_input_count32,
    &hfi_msg_islock_input_count64,
    &hfi_msg_islock_inputs,
    &hfi_msg_islock_txid,
    &hfi_msg_islock_sig,

  /* mnauth message: */
    &hfi_dash_msg_mnauth,
    &hfi_msg_mnauth_proregtx,
    &hfi_msg_mnauth_blssignature,

  /* qcontrib: */
    &hfi_dash_msg_qcontrib,
    &hfi_msg_qcontrib_llmq_type,
    &hfi_msg_qcontrib_quorum_hash,
    &hfi_msg_qcontrib_protx_hash,
    &hfi_msg_qcontrib_vvec_size8,
    &hfi_msg_qcontrib_vvec_size16,
    &hfi_msg_qcontrib_vvec_size32,
    &hfi_msg_qcontrib_vvec_size64,
    &hfi_msg_qcontrib_vvec,
    &hfi_msg_qcontrib_vvec_key,
    &hfi_msg_qcontrib_ephemeral_pubkey,
    &hfi_msg_qcontrib_iv,
    &hfi_msg_qcontrib_sk_count8,
    &hfi_msg_qcontrib_sk_count16,
    &hfi_msg_qcontrib_sk_count32,
    &hfi_msg_qcontrib_sk_count64,
    &hfi_msg_qcontrib_sk_contrib,
    &hfi_msg_qcontrib_sk_contrib_size,
    &hfi_msg_qcontrib_sk_contrib_key,
    &hfi_msg_qcontrib_sig,

  /* qcomplaint message */
    &hfi_dash_msg_qcomplaint,
    &hfi_msg_qcomplaint_llmq_type,
    &hfi_msg_qcomplaint_quorum_hash,
    &hfi_msg_qcomplaint_protx_hash,
    &hfi_msg_qcomplaint_badbit_size8,
    &hfi_msg_qcomplaint_badbit_size16,
    &hfi_msg_qcomplaint_badbit_size32,
    &hfi_msg_qcomplaint_badbit_size64,
    &hfi_msg_qcomplaint_badmembers,
    &hfi_msg_qcomplaint_complaintbit_size8,
    &hfi_msg_qcomplaint_complaintbit_size16,
    &hfi_msg_qcomplaint_complaintbit_size32,
    &hfi_msg_qcomplaint_complaintbit_size64,
    &hfi_msg_qcomplaint_complaints,
    &hfi_msg_qcomplaint_sig,

  /* qjustify */
    &hfi_dash_msg_qjustify,
    &hfi_msg_qjustify_llmq_type,
    &hfi_msg_qjustify_quorum_hash,
    &hfi_msg_qjustify_protx_hash,
    &hfi_msg_qjustify_sk_count8,
    &hfi_msg_qjustify_sk_count16,
    &hfi_msg_qjustify_sk_count32,
    &hfi_msg_qjustify_sk_count64,
    &hfi_msg_qjustify_sk_justify,
    &hfi_msg_qjustify_sk_justify_idx,
    &hfi_msg_qjustify_sk_justify_key,
    &hfi_msg_qjustify_sig,

  /* qpcommit */
    &hfi_dash_msg_qpcommit,
    &hfi_msg_qpcommit_llmq_type,
    &hfi_msg_qpcommit_quorum_hash,
    &hfi_msg_qpcommit_protx_hash,
    &hfi_msg_qpcommit_validmember_size8,
    &hfi_msg_qpcommit_validmember_size16,
    &hfi_msg_qpcommit_validmember_size32,
    &hfi_msg_qpcommit_validmember_size64,
    &hfi_msg_qpcommit_validmembers,
    &hfi_msg_qpcommit_quorum_pubkey,
    &hfi_msg_qpcommit_quorum_vvec_hash,
    &hfi_msg_qpcommit_quorum_sig,
    &hfi_msg_qpcommit_sig,

  /* qfcommit */
    &hfi_dash_msg_qfcommit,
    &hfi_msg_qfcommit_version,
    &hfi_msg_qfcommit_llmq_type,
    &hfi_msg_qfcommit_quorum_hash,
    &hfi_msg_qfcommit_singers_size8,
    &hfi_msg_qfcommit_singers_size16,
    &hfi_msg_qfcommit_singers_size32,
    &hfi_msg_qfcommit_singers_size64,
    &hfi_msg_qfcommit_singers,
    &hfi_msg_qfcommit_validmember_size8,
    &hfi_msg_qfcommit_validmember_size16,
    &hfi_msg_qfcommit_validmember_size32,
    &hfi_msg_qfcommit_validmember_size64,
    &hfi_msg_qfcommit_validmembers,
    &hfi_msg_qfcommit_quorum_pubkey,
    &hfi_msg_qfcommit_quorum_vvec_hash,
    &hfi_msg_qfcommit_quorum_sig,
    &hfi_msg_qfcommit_sig,

  /* qbsigs */
    &hfi_dash_msg_qbsigs,
    &hfi_msg_qbsigs_batchcount8,
    &hfi_msg_qbsigs_batchcount16,
    &hfi_msg_qbsigs_batchcount32,
    &hfi_msg_qbsigs_batchcount64,
    &hfi_msg_qbsigs_batched_sigshares,
    &hfi_msg_qbsigs_batched_sigshares_sessionid,
    &hfi_msg_qbsigs_batched_sigshares_sharecount8,
    &hfi_msg_qbsigs_batched_sigshares_sharecount16,
    &hfi_msg_qbsigs_batched_sigshares_sharecount32,
    &hfi_msg_qbsigs_batched_sigshares_sharecount64,
    &hfi_msg_qbsigs_batched_sigshares_sigshares,
    &hfi_msg_qbsigs_batched_sigshares_sigshares_index,
    &hfi_msg_qbsigs_batched_sigshares_sigshares_sig,

  /* qgetsigs */
    &hfi_dash_msg_qgetsigs,
    &hfi_msg_qgetsigs_count8,
    &hfi_msg_qgetsigs_count16,
    &hfi_msg_qgetsigs_count32,
    &hfi_msg_qgetsigs_count64,
    &hfi_msg_qgetsigs_sigs,
    &hfi_msg_qgetsigs_sigs_sessionid,
    &hfi_msg_qgetsigs_sigs_invsize8,
    &hfi_msg_qgetsigs_sigs_invsize16,
    &hfi_msg_qgetsigs_sigs_invsize32,
    &hfi_msg_qgetsigs_sigs_invsize64,
    &hfi_msg_qgetsigs_sigs_inv,

  /* qsendrecsigs message: */
    &hfi_dash_msg_qsendrecsigs,
    &hfi_msg_qsendrecsigs_enable,

  /* qsigrec */
    &hfi_dash_msg_qsigrec,
    &hfi_msg_qsigrec_llmq_type,
    &hfi_msg_qsigrec_quorumhash,
    &hfi_msg_qsigrec_id,
    &hfi_msg_qsigrec_msghash,
    &hfi_msg_qsigrec_sig,

  /* qsigsesann message: */
    &hfi_dash_msg_qsigsesann,
    &hfi_msg_qsigsesann_count8,
    &hfi_msg_qsigsesann_count16,
    &hfi_msg_qsigsesann_count32,
    &hfi_msg_qsigsesann_count64,
    &hfi_msg_qsigsesann_sesann,
    &hfi_msg_qsigsesann_sesann_sessionid,
    &hfi_msg_qsigsesann_sesann_llmq_type,
    &hfi_msg_qsigsesann_sesann_quorum_hash,
    &hfi_msg_qsigsesann_sesann_request_id,
    &hfi_msg_qsigsesann_sesann_message_hash,

/* qsigsinv */
    &hfi_dash_msg_qsigsinv,
    &hfi_msg_qsigsinv_count8,
    &hfi_msg_qsigsinv_count16,
    &hfi_msg_qsigsinv_count32,
    &hfi_msg_qsigsinv_count64,
    &hfi_msg_qsigsinv_sigs,
    &hfi_msg_qsigsinv_sigs_sessionid,
    &hfi_msg_qsigsinv_sigs_invsize8,
    &hfi_msg_qsigsinv_sigs_invsize16,
    &hfi_msg_qsigsinv_sigs_invsize32,
    &hfi_msg_qsigsinv_sigs_invsize64,
    &hfi_msg_qsigsinv_sigs_inv,
  };
#endif

  static gint *ett[] = {
    &ett_dash,
    &ett_dash_msg,
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
     { &ei_dash_command_unknown, { "dash.command.unknown", PI_PROTOCOL, PI_WARN, "Unknown command", EXPFILL }},
     { &ei_dash_script_len, { "dash.script_length.invalid", PI_MALFORMED, PI_ERROR, "script_len too large", EXPFILL }}
  };

  module_t *dash_module;
  expert_module_t* expert_dash;

  int proto_dash;

  proto_dash = proto_register_protocol("Dash protocol", "Dash", "dash");
  hfi_dash = proto_registrar_get_nth(proto_dash);

  proto_register_subtree_array(ett, array_length(ett));
  proto_register_fields(proto_dash, hfi, array_length(hfi));

  expert_dash = expert_register_protocol(proto_dash);
  expert_register_field_array(expert_dash, ei, array_length(ei));

  dash_command_table = register_dissector_table("dash.command", "Dash Command", proto_dash, FT_STRING, BASE_NONE);

  dash_handle = register_dissector("dash", dissect_dash, proto_dash);

  dash_module = prefs_register_protocol(proto_dash, NULL);
  prefs_register_bool_preference(dash_module, "desegment",
                                 "Desegment all Dash messages spanning multiple TCP segments",
                                 "Whether the Dash dissector should desegment all messages"
                                 " spanning multiple TCP segments",
                                 &dash_desegment);

}

void
proto_reg_handoff_dash(void)
{
  dissector_handle_t command_handle;

  dissector_add_for_decode_as("tcp.port", dash_handle);
  //dissector_add_for_decode_as_with_preference("tcp.port", dash_handle);

  heur_dissector_add( "tcp", dissect_dash_heur, "Dash over TCP", "dash_tcp", hfi_dash->id, HEURISTIC_ENABLE);

  /* Register all of the commands */
  command_handle = create_dissector_handle( dissect_dash_msg_version, hfi_dash->id );
  dissector_add_string("dash.command", "version", command_handle);
  command_handle = create_dissector_handle( dissect_dash_msg_addr, hfi_dash->id );
  dissector_add_string("dash.command", "addr", command_handle);
  command_handle = create_dissector_handle( dissect_dash_msg_inv, hfi_dash->id );
  dissector_add_string("dash.command", "inv", command_handle);
  command_handle = create_dissector_handle( dissect_dash_msg_getdata, hfi_dash->id );
  dissector_add_string("dash.command", "getdata", command_handle);
  command_handle = create_dissector_handle( dissect_dash_msg_getblocks, hfi_dash->id );
  dissector_add_string("dash.command", "getblocks", command_handle);
  command_handle = create_dissector_handle( dissect_dash_msg_getheaders, hfi_dash->id );
  dissector_add_string("dash.command", "getheaders", command_handle);
  command_handle = create_dissector_handle( dissect_dash_msg_tx, hfi_dash->id );
  dissector_add_string("dash.command", "tx", command_handle);
  command_handle = create_dissector_handle( dissect_dash_msg_block, hfi_dash->id );
  dissector_add_string("dash.command", "block", command_handle);
  command_handle = create_dissector_handle( dissect_dash_msg_ping, hfi_dash->id );
  dissector_add_string("dash.command", "ping", command_handle);
  command_handle = create_dissector_handle( dissect_dash_msg_pong, hfi_dash->id );
  dissector_add_string("dash.command", "pong", command_handle);
  command_handle = create_dissector_handle( dissect_dash_msg_notfound, hfi_dash->id );
  dissector_add_string("dash.command", "notfound", command_handle);
  command_handle = create_dissector_handle( dissect_dash_msg_reject, hfi_dash->id );
  dissector_add_string("dash.command", "reject", command_handle);
  command_handle = create_dissector_handle( dissect_dash_msg_headers, hfi_dash->id );
  dissector_add_string("dash.command", "headers", command_handle);
  command_handle = create_dissector_handle( dissect_dash_msg_filterload, hfi_dash->id );
  dissector_add_string("dash.command", "filterload", command_handle);
  command_handle = create_dissector_handle( dissect_dash_msg_filteradd, hfi_dash->id );
  dissector_add_string("dash.command", "filteradd", command_handle);
  command_handle = create_dissector_handle( dissect_dash_msg_merkleblock, hfi_dash->id );
  dissector_add_string("dash.command", "merkleblock", command_handle);

  command_handle = create_dissector_handle( dissect_dash_msg_blocktxn, hfi_dash->id );
  dissector_add_string("dash.command", "blocktxn", command_handle);
  command_handle = create_dissector_handle( dissect_dash_msg_cmpctblock, hfi_dash->id );
  dissector_add_string("dash.command", "cmpctblock", command_handle);
  command_handle = create_dissector_handle( dissect_dash_msg_getblocktxn, hfi_dash->id );
  dissector_add_string("dash.command", "getblocktxn", command_handle);
  command_handle = create_dissector_handle( dissect_dash_msg_sendcmpct, hfi_dash->id );
  dissector_add_string("dash.command", "sendcmpct", command_handle);

  /* Dash specific commands */
  command_handle = create_dissector_handle( dissect_dash_msg_mnb, hfi_dash->id );
  dissector_add_string("dash.command", "mnb", command_handle);
  command_handle = create_dissector_handle( dissect_dash_msg_mnp, hfi_dash->id );
  dissector_add_string("dash.command", "mnp", command_handle);
  command_handle = create_dissector_handle( dissect_dash_msg_mnw, hfi_dash->id );
  dissector_add_string("dash.command", "mnw", command_handle);
  command_handle = create_dissector_handle( dissect_dash_msg_mnwb, hfi_dash->id );
  dissector_add_string("dash.command", "mnwb", command_handle);
  command_handle = create_dissector_handle( dissect_dash_msg_mnv, hfi_dash->id );
  dissector_add_string("dash.command", "mnv", command_handle);

  command_handle = create_dissector_handle( dissect_dash_msg_dstx, hfi_dash->id );
  dissector_add_string("dash.command", "dstx", command_handle);
  command_handle = create_dissector_handle( dissect_dash_msg_dssu, hfi_dash->id );
  dissector_add_string("dash.command", "dssu", command_handle);
  command_handle = create_dissector_handle( dissect_dash_msg_dsq, hfi_dash->id );
  dissector_add_string("dash.command", "dsq", command_handle);
  command_handle = create_dissector_handle( dissect_dash_msg_dsa, hfi_dash->id );
  dissector_add_string("dash.command", "dsa", command_handle);
  command_handle = create_dissector_handle( dissect_dash_msg_dsi, hfi_dash->id );
  dissector_add_string("dash.command", "dsi", command_handle);
  command_handle = create_dissector_handle( dissect_dash_msg_dsf, hfi_dash->id );
  dissector_add_string("dash.command", "dsf", command_handle);
  command_handle = create_dissector_handle( dissect_dash_msg_dss, hfi_dash->id );
  dissector_add_string("dash.command", "dss", command_handle);
  command_handle = create_dissector_handle( dissect_dash_msg_dsc, hfi_dash->id );
  dissector_add_string("dash.command", "dsc", command_handle);
  command_handle = create_dissector_handle( dissect_dash_msg_ix, hfi_dash->id );
  dissector_add_string("dash.command", "ix", command_handle);
  command_handle = create_dissector_handle( dissect_dash_msg_txlvote, hfi_dash->id );
  dissector_add_string("dash.command", "txlvote", command_handle);
  command_handle = create_dissector_handle( dissect_dash_msg_govobj, hfi_dash->id );
  dissector_add_string("dash.command", "govobj", command_handle);
  command_handle = create_dissector_handle( dissect_dash_msg_govobjvote, hfi_dash->id );
  dissector_add_string("dash.command", "govobjvote", command_handle);
  command_handle = create_dissector_handle( dissect_dash_msg_govsync, hfi_dash->id );
  dissector_add_string("dash.command", "govsync", command_handle);

  command_handle = create_dissector_handle( dissect_dash_msg_spork, hfi_dash->id );
  dissector_add_string("dash.command", "spork", command_handle);
  command_handle = create_dissector_handle( dissect_dash_msg_dseg, hfi_dash->id );
  dissector_add_string("dash.command", "dseg", command_handle);
  command_handle = create_dissector_handle( dissect_dash_msg_ssc, hfi_dash->id );
  dissector_add_string("dash.command", "ssc", command_handle);
  command_handle = create_dissector_handle( dissect_dash_msg_mnget, hfi_dash->id );
  dissector_add_string("dash.command", "mnget", command_handle);

  /* messages with no payload */
  command_handle = create_dissector_handle( dissect_dash_msg_empty, hfi_dash->id );
  dissector_add_string("dash.command", "verack", command_handle);
  dissector_add_string("dash.command", "getaddr", command_handle);
  dissector_add_string("dash.command", "mempool", command_handle);
  dissector_add_string("dash.command", "filterclear", command_handle);
  dissector_add_string("dash.command", "sendheaders", command_handle);
  dissector_add_string("dash.command", "getsporks", command_handle);
  dissector_add_string("dash.command", "qwatch", command_handle);

  /* messages not implemented */
  /* command_handle = create_dissector_handle( dissect_dash_msg_empty, hfi_dash->id ); */
  dissector_add_string("dash.command", "checkorder", command_handle);
  dissector_add_string("dash.command", "submitorder", command_handle);
  dissector_add_string("dash.command", "reply", command_handle);
  dissector_add_string("dash.command", "alert", command_handle);
  command_handle = create_dissector_handle( dissect_dash_msg_getmnlistd, hfi_dash->id );
  dissector_add_string("dash.command", "getmnlistd", command_handle);
  command_handle = create_dissector_handle( dissect_dash_msg_mnlistdiff, hfi_dash->id );
  dissector_add_string("dash.command", "mnlistdiff", command_handle);
  command_handle = create_dissector_handle( dissect_dash_msg_senddsq, hfi_dash->id );
  dissector_add_string("dash.command", "senddsq", command_handle);
  command_handle = create_dissector_handle( dissect_dash_msg_clsig, hfi_dash->id );
  dissector_add_string("dash.command", "clsig", command_handle);
  command_handle = create_dissector_handle( dissect_dash_msg_islock, hfi_dash->id );
  dissector_add_string("dash.command", "islock", command_handle);
  command_handle = create_dissector_handle( dissect_dash_msg_mnauth, hfi_dash->id );
  dissector_add_string("dash.command", "mnauth", command_handle);
  command_handle = create_dissector_handle( dissect_dash_msg_qcontrib, hfi_dash->id );
  dissector_add_string("dash.command", "qcontrib", command_handle);
  command_handle = create_dissector_handle( dissect_dash_msg_qcomplaint, hfi_dash->id );
  dissector_add_string("dash.command", "qcomplaint", command_handle);
  command_handle = create_dissector_handle( dissect_dash_msg_qjustify, hfi_dash->id );
  dissector_add_string("dash.command", "qjustify", command_handle);
  command_handle = create_dissector_handle( dissect_dash_msg_qpcommit, hfi_dash->id );
  dissector_add_string("dash.command", "qpcommit", command_handle);
  command_handle = create_dissector_handle( dissect_dash_msg_qfcommit, hfi_dash->id );
  dissector_add_string("dash.command", "qfcommit", command_handle);
  command_handle = create_dissector_handle( dissect_dash_msg_qbsigs, hfi_dash->id );
  dissector_add_string("dash.command", "qbsigs", command_handle);
  command_handle = create_dissector_handle( dissect_dash_msg_qgetsigs, hfi_dash->id );
  dissector_add_string("dash.command", "qgetsigs", command_handle);
  command_handle = create_dissector_handle( dissect_dash_msg_qsendrecsigs, hfi_dash->id );
  dissector_add_string("dash.command", "qsendrecsigs", command_handle);
  command_handle = create_dissector_handle( dissect_dash_msg_qsigrec, hfi_dash->id );
  dissector_add_string("dash.command", "qsigrec", command_handle);
  command_handle = create_dissector_handle( dissect_dash_msg_qsigsesann, hfi_dash->id );
  dissector_add_string("dash.command", "qsigsesann", command_handle);
  command_handle = create_dissector_handle( dissect_dash_msg_qsigsinv, hfi_dash->id );
  dissector_add_string("dash.command", "qsigsinv", command_handle);
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
