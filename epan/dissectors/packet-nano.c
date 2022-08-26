/* packet-nano.c
 * Routines for Nano / RaiBlocks dissection
 * Copyright 2018, Roland Haenel <roland@haenel.me>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/*
 * For information about Nano / RaiBlocks, go to http://www.nano.org
 */

#include <config.h>

#include <conversation.h>
#include <packet-tcp.h>
#include <proto_data.h>

#include <epan/packet.h>
#include <epan/to_str.h>
#include <wsutil/str_util.h>

void proto_reg_handoff_nano(void);
void proto_register_nano(void);

static dissector_handle_t nano_handle, nano_tcp_handle;

static int proto_nano = -1;

static int hf_nano_magic_number = -1;
static int hf_nano_version_max = -1;
static int hf_nano_version_using = -1;
static int hf_nano_version_min = -1;
static int hf_nano_packet_type = -1;
static int hf_nano_extensions = -1;
static int hf_nano_extensions_block_type = -1;
static int hf_nano_keepalive_peer_ip = -1;
static int hf_nano_keepalive_peer_port = -1;

static int hf_nano_block_hash_previous = -1;
static int hf_nano_block_hash_source = -1;
static int hf_nano_block_signature = -1;
static int hf_nano_block_work = -1;
static int hf_nano_block_destination_account = -1;
static int hf_nano_block_balance = -1;
static int hf_nano_block_account = -1;
static int hf_nano_block_representative_account = -1;
static int hf_nano_block_link = -1;

static int hf_nano_vote_account = -1;
static int hf_nano_vote_signature = -1;
static int hf_nano_vote_sequence = -1;

static int hf_nano_bulk_pull_account = -1;
static int hf_nano_bulk_pull_block_hash_end = -1;

static int hf_nano_frontier_req_account = -1;
static int hf_nano_frontier_req_age = -1;
static int hf_nano_frontier_req_count = -1;

static int hf_nano_bulk_pull_blocks_min_hash = -1;
static int hf_nano_bulk_pull_blocks_max_hash = -1;
static int hf_nano_bulk_pull_blocks_mode = -1;
static int hf_nano_bulk_pull_blocks_max_count = -1;

static int hf_nano_bulk_push_block_type = -1;

static int hf_nano_bulk_pull_block_type = -1;

static int hf_nano_frontier_account = -1;
static int hf_nano_frontier_head_hash = -1;

static gint ett_nano = -1;
static gint ett_nano_header = -1;
static gint ett_nano_extensions = -1;
static gint ett_nano_peers = -1;
static gint ett_nano_peer_details[8] = {-1, -1, -1, -1, -1, -1, -1, -1};
static gint ett_nano_block = -1;
static gint ett_nano_vote = -1;
static gint ett_nano_bulk_pull = -1;
static gint ett_nano_frontier_req = -1;
static gint ett_nano_bulk_pull_blocks = -1;
static gint ett_nano_frontier = -1;

#define NANO_PACKET_TYPE_INVALID 0
#define NANO_PACKET_TYPE_NOT_A_TYPE 1
#define NANO_PACKET_TYPE_KEEPALIVE 2
#define NANO_PACKET_TYPE_PUBLISH 3
#define NANO_PACKET_TYPE_CONFIRM_REQ 4
#define NANO_PACKET_TYPE_CONFIRM_ACK 5
#define NANO_PACKET_TYPE_BULK_PULL 6
#define NANO_PACKET_TYPE_BULK_PUSH 7
#define NANO_PACKET_TYPE_FRONTIER_REQ 8
#define NANO_PACKET_TYPE_BULK_PULL_BLOCKS 9

static const value_string nano_packet_type_strings[] = {
  { NANO_PACKET_TYPE_INVALID, "Invalid" },
  { NANO_PACKET_TYPE_NOT_A_TYPE, "Not A Type" },
  { NANO_PACKET_TYPE_KEEPALIVE, "Keepalive" },
  { NANO_PACKET_TYPE_PUBLISH, "Publish" },
  { NANO_PACKET_TYPE_CONFIRM_REQ, "Confirm Req" },
  { NANO_PACKET_TYPE_CONFIRM_ACK, "Confirm Ack" },
  { NANO_PACKET_TYPE_BULK_PULL, "Bulk Pull" },
  { NANO_PACKET_TYPE_BULK_PUSH, "Bulk Push" },
  { NANO_PACKET_TYPE_FRONTIER_REQ, "Frontier Req" },
  { NANO_PACKET_TYPE_BULK_PULL_BLOCKS, "Bulk Pull Blocks" },
  { 0, NULL },
};

#define NANO_BLOCK_TYPE_INVALID 0
#define NANO_BLOCK_TYPE_NOT_A_BLOCK 1
#define NANO_BLOCK_TYPE_SEND 2
#define NANO_BLOCK_TYPE_RECEIVE 3
#define NANO_BLOCK_TYPE_OPEN 4
#define NANO_BLOCK_TYPE_CHANGE 5
#define NANO_BLOCK_TYPE_STATE 6

static const value_string nano_block_type_strings[] = {
  { NANO_BLOCK_TYPE_INVALID, "Invalid" },
  { NANO_BLOCK_TYPE_NOT_A_BLOCK, "Not A Block" },
  { NANO_BLOCK_TYPE_SEND, "Send" },
  { NANO_BLOCK_TYPE_RECEIVE, "Receive" },
  { NANO_BLOCK_TYPE_OPEN, "Open" },
  { NANO_BLOCK_TYPE_CHANGE, "Change" },
  { NANO_BLOCK_TYPE_STATE, "State" },
  { 0, NULL },
};

static const string_string nano_magic_numbers[] = {
    { "RA", "Nano Test Network" },
    { "RB", "Nano Beta Network" },
    { "RC", "Nano Production Network" },
    { 0, NULL }
};

#define NANO_BULK_PULL_BLOCKS_MODE_LIST_BLOCKS 0
#define NANO_BULK_PULL_BLOCKS_MODE_CHECKSUM_BLOCKS 1

static const value_string nano_bulk_pull_blocks_mode_strings[] = {
  { NANO_BULK_PULL_BLOCKS_MODE_LIST_BLOCKS, "List Blocks" },
  { NANO_BULK_PULL_BLOCKS_MODE_CHECKSUM_BLOCKS, "Checksum Blocks" },
  { 0, NULL },
};

#define NANO_UDP_PORT 7075 /* Not IANA registered */
#define NANO_TCP_PORT 7075 /* Not IANA registered */

#define NANO_BLOCK_SIZE_SEND    (32+32+16+64+8)
#define NANO_BLOCK_SIZE_RECEIVE (32+32+64+8)
#define NANO_BLOCK_SIZE_OPEN    (32+32+32+64+8)
#define NANO_BLOCK_SIZE_CHANGE  (32+32+64+8)
#define NANO_BLOCK_SIZE_STATE   (32+32+32+16+32+64+8)

// Nano header length, and thus minimum length of any Nano UDP packet (or bootstrap request)
#define NANO_HEADER_LENGTH 8

// Nano bootstrap session state
struct nano_session_state {
    int client_packet_type;
    guint32 server_port;
};


// dissect the inside of a keepalive packet (that is, the neighbor nodes)
static int dissect_nano_keepalive(tvbuff_t *tvb, packet_info *pinfo, proto_tree *nano_tree, int offset)
{
    proto_item *ti;
    proto_tree *peer_tree, *peer_entry_tree;
    int i, peers;
    ws_in6_addr ip_addr;
    guint32 port;
    gchar buf[100];

    peer_tree = proto_tree_add_subtree(nano_tree, tvb, offset, 8*(16+2), ett_nano_peers, NULL, "Peer List");

    peers = 0;
    for (i = 0; i < 8; i++) {
        peer_entry_tree = proto_tree_add_subtree(peer_tree, tvb, offset, 18, ett_nano_peer_details[i], &ti, "Peer");

        tvb_get_ipv6(tvb, offset, &ip_addr);
        proto_tree_add_item(peer_entry_tree, hf_nano_keepalive_peer_ip, tvb, offset, 16, ENC_NA);
        offset += 16;

        proto_tree_add_item_ret_uint(peer_entry_tree, hf_nano_keepalive_peer_port, tvb, offset, 2, ENC_LITTLE_ENDIAN, &port);
        offset += 2;

        if (!memcmp(&ip_addr, "\x0\x0\x0\x0\x0\x0\x0\x0\x0\x0\x0\x0\x0\x0\x0\x0", 16)) {
            proto_item_append_text(ti, ": (none)");
        } else if (!memcmp(&ip_addr, "\x0\x0\x0\x0\x0\x0\x0\x0\x0\x0\xff\xff", 12)) {
            ip_to_str_buf((gchar *) &ip_addr + 12, buf, sizeof(buf));
            proto_item_append_text(ti, ": %s:%d", buf, port);
            peers++;
        } else {
            ip6_to_str_buf(&ip_addr, buf, sizeof(buf));
            proto_item_append_text(ti, ": [%s]:%d", buf, port);
            peers++;
        }
    }

    col_add_fstr(pinfo->cinfo, COL_INFO, "Keepalive (%d peer%s)", peers, plurality(peers, "", "s"));

    return offset;
}

// dissect a receive block
static int dissect_nano_receive_block(tvbuff_t *tvb, proto_tree *nano_tree, int offset)
{
    proto_tree *block_tree;

    block_tree = proto_tree_add_subtree(nano_tree, tvb, offset, NANO_BLOCK_SIZE_RECEIVE, ett_nano_block, NULL, "Receive Block");

    proto_tree_add_item(block_tree, hf_nano_block_hash_previous, tvb, offset, 32, ENC_NA);
    offset += 32;

    proto_tree_add_item(block_tree, hf_nano_block_hash_source, tvb, offset, 32, ENC_NA);
    offset += 32;

    proto_tree_add_item(block_tree, hf_nano_block_signature, tvb, offset, 64, ENC_NA);
    offset += 64;

    proto_tree_add_item(block_tree, hf_nano_block_work, tvb, offset, 8, ENC_NA);
    offset += 8;

    return offset;
}

// dissect a send block
static int dissect_nano_send_block(tvbuff_t *tvb, proto_tree *nano_tree, int offset)
{
    proto_tree *block_tree;

    block_tree = proto_tree_add_subtree(nano_tree, tvb, offset, NANO_BLOCK_SIZE_SEND, ett_nano_block, NULL, "Send Block");

    proto_tree_add_item(block_tree, hf_nano_block_hash_previous, tvb, offset, 32, ENC_NA);
    offset += 32;

    proto_tree_add_item(block_tree, hf_nano_block_destination_account, tvb, offset, 32, ENC_NA);
    offset += 32;

    proto_tree_add_item(block_tree, hf_nano_block_balance, tvb, offset, 16, ENC_NA);
    offset += 16;

    proto_tree_add_item(block_tree, hf_nano_block_signature, tvb, offset, 64, ENC_NA);
    offset += 64;

    proto_tree_add_item(block_tree, hf_nano_block_work, tvb, offset, 8, ENC_NA);
    offset += 8;

    return offset;
}

// dissect an open block
static int dissect_nano_open_block(tvbuff_t *tvb, proto_tree *nano_tree, int offset)
{
    proto_tree *block_tree;

    block_tree = proto_tree_add_subtree(nano_tree, tvb, offset, NANO_BLOCK_SIZE_OPEN, ett_nano_block, NULL, "Open Block");

    proto_tree_add_item(block_tree, hf_nano_block_hash_source, tvb, offset, 32, ENC_NA);
    offset += 32;

    proto_tree_add_item(block_tree, hf_nano_block_representative_account, tvb, offset, 32, ENC_NA);
    offset += 32;

    proto_tree_add_item(block_tree, hf_nano_block_account, tvb, offset, 32, ENC_NA);
    offset += 32;

    proto_tree_add_item(block_tree, hf_nano_block_signature, tvb, offset, 64, ENC_NA);
    offset += 64;

    proto_tree_add_item(block_tree, hf_nano_block_work, tvb, offset, 8, ENC_NA);
    offset += 8;

    return offset;
}

// dissect an change block
static int dissect_nano_change_block(tvbuff_t *tvb, proto_tree *nano_tree, int offset)
{
    proto_tree *block_tree;

    block_tree = proto_tree_add_subtree(nano_tree, tvb, offset, NANO_BLOCK_SIZE_CHANGE, ett_nano_block, NULL, "Change Block");

    proto_tree_add_item(block_tree, hf_nano_block_hash_previous, tvb, offset, 32, ENC_NA);
    offset += 32;

    proto_tree_add_item(block_tree, hf_nano_block_representative_account, tvb, offset, 32, ENC_NA);
    offset += 32;

    proto_tree_add_item(block_tree, hf_nano_block_signature, tvb, offset, 64, ENC_NA);
    offset += 64;

    proto_tree_add_item(block_tree, hf_nano_block_work, tvb, offset, 8, ENC_NA);
    offset += 8;

    return offset;
}

// dissect a state block
static int dissect_nano_state(tvbuff_t *tvb, proto_tree *nano_tree, int offset)
{
    proto_tree *block_tree;

    block_tree = proto_tree_add_subtree(nano_tree, tvb, offset, NANO_BLOCK_SIZE_STATE, ett_nano_block, NULL, "State Block");

    proto_tree_add_item(block_tree, hf_nano_block_account, tvb, offset, 32, ENC_NA);
    offset += 32;

    proto_tree_add_item(block_tree, hf_nano_block_hash_previous, tvb, offset, 32, ENC_NA);
    offset += 32;

    proto_tree_add_item(block_tree, hf_nano_block_representative_account, tvb, offset, 32, ENC_NA);
    offset += 32;

    proto_tree_add_item(block_tree, hf_nano_block_balance, tvb, offset, 16, ENC_NA);
    offset += 16;

    proto_tree_add_item(block_tree, hf_nano_block_link, tvb, offset, 32, ENC_NA);
    offset += 32;

    proto_tree_add_item(block_tree, hf_nano_block_signature, tvb, offset, 64, ENC_NA);
    offset += 64;

    proto_tree_add_item(block_tree, hf_nano_block_work, tvb, offset, 8, ENC_NA);
    offset += 8;

    return offset;
}

// dissect a vote
static int dissect_nano_vote(tvbuff_t *tvb, proto_tree *nano_tree, int offset)
{
    proto_tree *vote_tree;

    vote_tree = proto_tree_add_subtree(nano_tree, tvb, offset, 32+64+8, ett_nano_block, NULL, "Vote");

    proto_tree_add_item(vote_tree, hf_nano_vote_account, tvb, offset, 32, ENC_NA);
    offset += 32;

    proto_tree_add_item(vote_tree, hf_nano_vote_signature, tvb, offset, 64, ENC_NA);
    offset += 64;

    proto_tree_add_item(vote_tree, hf_nano_vote_sequence, tvb, offset, 8, ENC_LITTLE_ENDIAN);
    offset += 8;

    return offset;
}

// dissect a Nano protocol header, fills in the values
// for nano_packet_type, nano_block_type
static int dissect_nano_header(tvbuff_t *tvb, packet_info *pinfo, proto_tree *nano_tree, int offset, guint *nano_packet_type, guint64 *extensions)
{
    proto_tree *header_tree;
    char *nano_magic_number;
    static int * const nano_extensions[] = {
        &hf_nano_extensions_block_type,
        NULL
    };

    header_tree = proto_tree_add_subtree(nano_tree, tvb, offset, NANO_HEADER_LENGTH, ett_nano_header, NULL, "Nano Protocol Header");

    nano_magic_number = tvb_get_string_enc(pinfo->pool, tvb, offset, 2, ENC_ASCII);
    proto_tree_add_string_format_value(header_tree, hf_nano_magic_number, tvb, 0,
            2, nano_magic_number, "%s (%s)", str_to_str(nano_magic_number, nano_magic_numbers, "Unknown"), nano_magic_number);
    offset += 2;

    proto_tree_add_item(header_tree, hf_nano_version_max, tvb, offset, 1, ENC_NA);
    offset += 1;

    proto_tree_add_item(header_tree, hf_nano_version_using, tvb, offset, 1, ENC_NA);
    offset += 1;

    proto_tree_add_item(header_tree, hf_nano_version_min, tvb, offset, 1, ENC_NA);
    offset += 1;

    proto_tree_add_item_ret_uint(header_tree, hf_nano_packet_type, tvb, offset, 1, ENC_NA, nano_packet_type);
    offset += 1;

    proto_tree_add_bitmask_ret_uint64(header_tree, tvb, offset, hf_nano_extensions, ett_nano_extensions, nano_extensions, ENC_LITTLE_ENDIAN, extensions);
    offset += 2;

    return offset;
}

// dissect a Nano packet (UDP)
static int dissect_nano(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    proto_item *ti;
    proto_tree *nano_tree;
    guint nano_packet_type, nano_block_type, offset;
    guint64 extensions;

    /* Check that the packet is long enough for it to belong to us. */
    if (tvb_reported_length(tvb) < NANO_HEADER_LENGTH)
        return 0;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "Nano");
    col_clear(pinfo->cinfo, COL_INFO);

    ti = proto_tree_add_item(tree, proto_nano, tvb, 0, -1, ENC_NA);
    nano_tree = proto_item_add_subtree(ti, ett_nano);

    offset = dissect_nano_header(tvb, pinfo, nano_tree, 0, &nano_packet_type, &extensions);

    // call specific dissectors for specific packet types
    switch (nano_packet_type) {
        case NANO_PACKET_TYPE_KEEPALIVE:
            return dissect_nano_keepalive(tvb, pinfo, nano_tree, offset);

        case NANO_PACKET_TYPE_PUBLISH:
        case NANO_PACKET_TYPE_CONFIRM_REQ:
        case NANO_PACKET_TYPE_CONFIRM_ACK:

            // set the INFO header with more information
            nano_block_type = (guint)((extensions >> 8) & 0xF);
            col_add_fstr(pinfo->cinfo, COL_INFO, "%s (%s)",
                    val_to_str_const(nano_packet_type, VALS(nano_packet_type_strings), " "),
                    val_to_str(nano_block_type, VALS(nano_block_type_strings), "Unknown (%d)"));

            // if it's a Confirm Ack packet, we first have a vote
            if (nano_packet_type == NANO_PACKET_TYPE_CONFIRM_ACK) {
                offset = dissect_nano_vote(tvb, nano_tree, offset);
            }

            // dissect the actual block
            switch (nano_block_type) {
                case NANO_BLOCK_TYPE_RECEIVE:
                    dissect_nano_receive_block(tvb, nano_tree, offset);
                    break;
                case NANO_BLOCK_TYPE_SEND:
                    dissect_nano_send_block(tvb, nano_tree, offset);
                    break;
                case NANO_BLOCK_TYPE_OPEN:
                    dissect_nano_open_block(tvb, nano_tree, offset);
                    break;
                case NANO_BLOCK_TYPE_CHANGE:
                    dissect_nano_change_block(tvb, nano_tree, offset);
                    break;
                case NANO_BLOCK_TYPE_STATE:
                    dissect_nano_state(tvb, nano_tree, offset);
                    break;
            }
            break;

        default:
            col_add_str(pinfo->cinfo, COL_INFO,
                    val_to_str(nano_packet_type, VALS(nano_packet_type_strings), "Unknown (%d)"));
    }

    return tvb_captured_length(tvb);
}

// determine the length of a nano bootstrap message (client)
static guint get_nano_tcp_client_message_len(packet_info *pinfo _U_, tvbuff_t *tvb, int offset, void *data _U_)
{
    int nano_packet_type, nano_block_type;
    struct nano_session_state *session_state;

    session_state = (struct nano_session_state *)data;
    if (session_state->client_packet_type == NANO_PACKET_TYPE_BULK_PUSH) {
        // we're in the middle of a bulk push, so we expect a block type (uint8) and a block

        nano_block_type = tvb_get_guint8(tvb, offset);
        switch (nano_block_type) {
            case NANO_BLOCK_TYPE_NOT_A_BLOCK:
                return 1;
            case NANO_BLOCK_TYPE_SEND:
                return 1 + NANO_BLOCK_SIZE_SEND;
            case NANO_BLOCK_TYPE_RECEIVE:
                return 1 + NANO_BLOCK_SIZE_RECEIVE;
            case NANO_BLOCK_TYPE_OPEN:
                return 1 + NANO_BLOCK_SIZE_OPEN;
            case NANO_BLOCK_TYPE_CHANGE:
                return 1 + NANO_BLOCK_SIZE_CHANGE;
            case NANO_BLOCK_TYPE_STATE:
                return 1 + NANO_BLOCK_SIZE_STATE;
            default:
                // this is invalid
                return tvb_captured_length(tvb) - offset;
        }
    }

    // we expect a client command, this starts with a full Nano header
    if (tvb_captured_length(tvb) - offset < NANO_HEADER_LENGTH) {
        return 0;
    }

    nano_packet_type = tvb_get_guint8(tvb, offset + 5);

    switch (nano_packet_type) {
        case NANO_PACKET_TYPE_BULK_PULL:
            return NANO_HEADER_LENGTH + 32 + 32;
        case NANO_PACKET_TYPE_BULK_PUSH:
            return NANO_HEADER_LENGTH;
        case NANO_PACKET_TYPE_FRONTIER_REQ:
            return NANO_HEADER_LENGTH + 32 + 4 + 4;
        case NANO_PACKET_TYPE_BULK_PULL_BLOCKS:
            return NANO_HEADER_LENGTH + 32 + 32 + 1 + 4;
    }

    return tvb_captured_length(tvb) - offset;
}

// dissect a bulk pull request
static int dissect_nano_bulk_pull(tvbuff_t *tvb, proto_tree *nano_tree, int offset)
{
    proto_tree *vote_tree;

    vote_tree = proto_tree_add_subtree(nano_tree, tvb, offset, 32+32, ett_nano_bulk_pull, NULL, "Bulk Pull");

    proto_tree_add_item(vote_tree, hf_nano_bulk_pull_account, tvb, offset, 32, ENC_NA);
    offset += 32;

    proto_tree_add_item(vote_tree, hf_nano_bulk_pull_block_hash_end, tvb, offset, 32, ENC_NA);
    offset += 32;

    return offset;
}

// dissect a frontier request
static int dissect_nano_frontier_req(tvbuff_t *tvb, proto_tree *nano_tree, int offset)
{
    proto_tree *vote_tree;

    vote_tree = proto_tree_add_subtree(nano_tree, tvb, offset, 32+4+4, ett_nano_frontier_req, NULL, "Frontier Request");

    proto_tree_add_item(vote_tree, hf_nano_frontier_req_account, tvb, offset, 32, ENC_NA);
    offset += 32;

    proto_tree_add_item(vote_tree, hf_nano_frontier_req_age, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;

    proto_tree_add_item(vote_tree, hf_nano_frontier_req_count, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;

    return offset;
}

// dissect a bulk pull blocks request
static int dissect_nano_bulk_pull_blocks(tvbuff_t *tvb, proto_tree *nano_tree, int offset)
{
    proto_tree *vote_tree;

    vote_tree = proto_tree_add_subtree(nano_tree, tvb, offset, 32+4+4, ett_nano_frontier_req, NULL, "Bulk Pull Blocks");

    proto_tree_add_item(vote_tree, hf_nano_bulk_pull_blocks_min_hash, tvb, offset, 32, ENC_NA);
    offset += 32;

    proto_tree_add_item(vote_tree, hf_nano_bulk_pull_blocks_max_hash, tvb, offset, 32, ENC_NA);
    offset += 32;

    proto_tree_add_item(nano_tree, hf_nano_bulk_pull_blocks_mode, tvb, offset, 1, ENC_NA);
    offset += 1;

    proto_tree_add_item(vote_tree, hf_nano_bulk_pull_blocks_max_count, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;

    return offset;
}

// dissect a single nano bootstrap message (client)
static int dissect_nano_tcp_client_message(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree _U_, void *data _U_)
{
    int offset, nano_packet_type, nano_block_type;
    guint64 extensions;
    struct nano_session_state *session_state;

    session_state = (struct nano_session_state *)data;

    if (session_state->client_packet_type == NANO_PACKET_TYPE_BULK_PUSH) {
        // we're within a bulk push
        col_set_str(pinfo->cinfo, COL_INFO, "Bulk Push ");
        proto_tree_add_item_ret_uint(tree, hf_nano_bulk_push_block_type, tvb, 0, 1, ENC_NA, &nano_block_type);
        switch (nano_block_type) {
            case NANO_BLOCK_TYPE_NOT_A_BLOCK:
                session_state->client_packet_type = NANO_PACKET_TYPE_INVALID;
                break;
            case NANO_BLOCK_TYPE_SEND:
                dissect_nano_send_block(tvb, tree, 1);
                break;
            case NANO_BLOCK_TYPE_RECEIVE:
                dissect_nano_receive_block(tvb, tree, 1);
                break;
            case NANO_BLOCK_TYPE_OPEN:
                dissect_nano_open_block(tvb, tree, 1);
                break;
            case NANO_BLOCK_TYPE_CHANGE:
                dissect_nano_change_block(tvb, tree, 1);
                break;
            case NANO_BLOCK_TYPE_STATE:
                dissect_nano_state(tvb, tree, 1);
                break;
        }
        return tvb_captured_length(tvb);
    }

    // a bootstrap client command starts with a Nano header
    offset = dissect_nano_header(tvb, pinfo, tree, 0, &nano_packet_type, &extensions);
    session_state->client_packet_type = nano_packet_type;

    switch (nano_packet_type) {
        case NANO_PACKET_TYPE_BULK_PULL:
            col_set_str(pinfo->cinfo, COL_INFO, "Bulk Pull Request ");
            dissect_nano_bulk_pull(tvb, tree, offset);
            break;
        case NANO_PACKET_TYPE_BULK_PUSH:
            col_set_str(pinfo->cinfo, COL_INFO, "Bulk Push Request ");
            break;
        case NANO_PACKET_TYPE_FRONTIER_REQ:
            col_set_str(pinfo->cinfo, COL_INFO, "Frontier Request ");
            dissect_nano_frontier_req(tvb, tree, offset);
            break;
        case NANO_PACKET_TYPE_BULK_PULL_BLOCKS:
            col_set_str(pinfo->cinfo, COL_INFO, "Bulk Pull Blocks Request ");
            dissect_nano_bulk_pull_blocks(tvb, tree, offset);
            break;
    }

    return tvb_captured_length(tvb);
}

// determine the length of a nano bootstrap message (server)
static guint get_nano_tcp_server_message_len(packet_info *pinfo _U_, tvbuff_t *tvb, int offset, void *data _U_)
{
    int nano_block_type;
    struct nano_session_state *session_state;

    session_state = (struct nano_session_state *)data;

    if (session_state->client_packet_type == NANO_PACKET_TYPE_BULK_PULL ||
        session_state->client_packet_type == NANO_PACKET_TYPE_BULK_PULL_BLOCKS) {
        // we're in response to a bulk pull (blocks), so we expect a block type (uint8) and a block

        nano_block_type = tvb_get_guint8(tvb, offset);
        switch (nano_block_type) {
            case NANO_BLOCK_TYPE_NOT_A_BLOCK:
                return 1;
            case NANO_BLOCK_TYPE_SEND:
                return 1 + NANO_BLOCK_SIZE_SEND;
            case NANO_BLOCK_TYPE_RECEIVE:
                return 1 + NANO_BLOCK_SIZE_RECEIVE;
            case NANO_BLOCK_TYPE_OPEN:
                return 1 + NANO_BLOCK_SIZE_OPEN;
            case NANO_BLOCK_TYPE_CHANGE:
                return 1 + NANO_BLOCK_SIZE_CHANGE;
            case NANO_BLOCK_TYPE_STATE:
                return 1 + NANO_BLOCK_SIZE_STATE;
            default:
                // this is invalid
                return tvb_captured_length(tvb) - offset;
        }
    }

    if (session_state->client_packet_type == NANO_PACKET_TYPE_FRONTIER_REQ) {
        return 32 + 32;
    }

    return tvb_captured_length(tvb) - offset;
}

// dissect a frontier response entry
static int dissect_nano_frontier(tvbuff_t *tvb, proto_tree *nano_tree, int offset)
{
    proto_tree *frontier_tree;

    frontier_tree = proto_tree_add_subtree(nano_tree, tvb, offset, 32+32, ett_nano_frontier, NULL, "Frontier");

    proto_tree_add_item(frontier_tree, hf_nano_frontier_account, tvb, offset, 32, ENC_NA);
    offset += 32;

    proto_tree_add_item(frontier_tree, hf_nano_frontier_head_hash, tvb, offset, 32, ENC_NA);
    offset += 32;

    return offset;
}

// dissect a single nano bootstrap message (server)
static int dissect_nano_tcp_server_message(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_)
{
    int nano_block_type;
    struct nano_session_state *session_state;

    session_state = (struct nano_session_state *)data;

    if (session_state->client_packet_type == NANO_PACKET_TYPE_BULK_PULL ||
        session_state->client_packet_type == NANO_PACKET_TYPE_BULK_PULL_BLOCKS) {

        // we're within a bulk pull (blocks)
        col_set_str(pinfo->cinfo, COL_INFO, session_state->client_packet_type == NANO_PACKET_TYPE_BULK_PULL ? "Bulk Pull Response " : "Bulk Pull Blocks Response ");

        proto_tree_add_item_ret_uint(tree, hf_nano_bulk_pull_block_type, tvb, 0, 1, ENC_NA, &nano_block_type);
        switch (nano_block_type) {
            case NANO_BLOCK_TYPE_NOT_A_BLOCK:
                session_state->client_packet_type = NANO_PACKET_TYPE_INVALID;
                break;
            case NANO_BLOCK_TYPE_SEND:
                dissect_nano_send_block(tvb, tree, 1);
                break;
            case NANO_BLOCK_TYPE_RECEIVE:
                dissect_nano_receive_block(tvb, tree, 1);
                break;
            case NANO_BLOCK_TYPE_OPEN:
                dissect_nano_open_block(tvb, tree, 1);
                break;
            case NANO_BLOCK_TYPE_CHANGE:
                dissect_nano_change_block(tvb, tree, 1);
                break;
            case NANO_BLOCK_TYPE_STATE:
                dissect_nano_state(tvb, tree, 1);
                break;
        }
        return tvb_captured_length(tvb);
    }

    if (session_state->client_packet_type == NANO_PACKET_TYPE_FRONTIER_REQ) {
        col_set_str(pinfo->cinfo, COL_INFO, "Frontier Response ");
        dissect_nano_frontier(tvb, tree, 0);
    }

    return tvb_captured_length(tvb);
}

// dissect a Nano bootstrap packet (TCP)
static int dissect_nano_tcp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    int is_client;
    proto_item *ti;
    proto_tree *nano_tree;
    conversation_t *conversation;
    struct nano_session_state *session_state, *packet_session_state;

    // try to find this conversation
    if ((conversation = find_conversation_pinfo(pinfo, 0)) == NULL) {
        // create new conversation
        conversation = conversation_new(pinfo->num, &pinfo->src, &pinfo->dst, conversation_pt_to_conversation_type(pinfo->ptype),
                pinfo->srcport, pinfo->destport, 0);
    }

    // try to find session state
    session_state = (struct nano_session_state *)conversation_get_proto_data(conversation, proto_nano);
    if (!session_state) {
        // create new session state
        session_state = wmem_new0(wmem_file_scope(), struct nano_session_state);
        session_state->client_packet_type = NANO_PACKET_TYPE_INVALID;
        session_state->server_port = pinfo->match_uint;
        conversation_add_proto_data(conversation, proto_nano, session_state);
    }

    // check if we have a session state associated with the packet (start state for this packet)
    packet_session_state = (struct nano_session_state *)p_get_proto_data(wmem_file_scope(), pinfo, proto_nano, 0);
    if (!packet_session_state) {
        // this packet does not have a stored session state, get it from the conversation
        packet_session_state = wmem_new0(wmem_file_scope(), struct nano_session_state);
        memcpy(packet_session_state, session_state, sizeof(struct nano_session_state));
        p_add_proto_data(wmem_file_scope(), pinfo, proto_nano, 0, packet_session_state);
    } else {
        // this packet has a stored session state, take this as a starting point
        memcpy(session_state, packet_session_state, sizeof(struct nano_session_state));
    }

    // set some columns to meaningful defaults
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "Nano Bootstrap");
    col_clear(pinfo->cinfo, COL_INFO);

    // add Nano protocol tree
    ti = proto_tree_add_item(tree, proto_nano, tvb, 0, -1, ENC_NA);
    nano_tree = proto_item_add_subtree(ti, ett_nano);

    // is this a bootstrap client or server?
    is_client = pinfo->destport == session_state->server_port;

    if (is_client) {
        // Nano bootstrap client
        tcp_dissect_pdus(tvb, pinfo, nano_tree, TRUE, 1, get_nano_tcp_client_message_len, dissect_nano_tcp_client_message, session_state);

    } else {
        // Nano bootstrap server
        tcp_dissect_pdus(tvb, pinfo, nano_tree, TRUE, 1, get_nano_tcp_server_message_len, dissect_nano_tcp_server_message, session_state);
    }

    return tvb_captured_length(tvb);
}

/* Heuristics test */
static gboolean test_nano(packet_info *pinfo _U_, tvbuff_t *tvb, int offset _U_, void *data _U_)
{
    // if it's not a complete header length, it's not Nano.
    if (tvb_captured_length(tvb) < NANO_HEADER_LENGTH)
        return FALSE;

    // first byte must be 'R', second byte 'A' or 'B' or 'C'
    if (tvb_get_guint8(tvb, 0) != (guint8) 'R')
        return FALSE;

    char network = (char) tvb_get_guint8(tvb, 1);
    if (network != 'A' && network != 'B' && network != 'C')
        return FALSE;

    guint8 version_max = tvb_get_guint8(tvb, 2);
    guint8 version_using = tvb_get_guint8(tvb, 3);
    guint8 version_min = tvb_get_guint8(tvb, 4);
    if (version_max > 30 || version_max < version_using || version_using < version_min)
        return FALSE;

    guint8 ptype = tvb_get_guint8(tvb, 5);
    if (ptype > 15)
        return FALSE;

    return TRUE;
}

static gboolean dissect_nano_heur_tcp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
    conversation_t *conversation;
    struct nano_session_state *session_state;

    if (!test_nano(pinfo, tvb, 0, data))
        return FALSE;

    conversation = find_or_create_conversation(pinfo);
    conversation_set_dissector(conversation, nano_tcp_handle);

    // try to find session state
    session_state = (struct nano_session_state *)conversation_get_proto_data(conversation, proto_nano);
    if (!session_state) {
        // create new session state
        session_state = wmem_new0(wmem_file_scope(), struct nano_session_state);
        session_state->client_packet_type = NANO_PACKET_TYPE_INVALID;
        session_state->server_port = pinfo->destport;
        conversation_add_proto_data(conversation, proto_nano, session_state);
    }

    dissect_nano_tcp(tvb, pinfo, tree, data);

    return TRUE;
}

static gboolean dissect_nano_heur_udp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
    conversation_t *conversation;

    if (!test_nano(pinfo, tvb, 0, data))
        return FALSE;

    conversation = find_or_create_conversation(pinfo);
    conversation_set_dissector(conversation, nano_handle);

    dissect_nano(tvb, pinfo, tree, data);

    return TRUE;
}

void proto_register_nano(void)
{
    static hf_register_info hf[] = {
        { &hf_nano_magic_number,
          { "Magic Number", "nano.magic_number",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "Nano Protocol Magic Number", HFILL }
        },
        { &hf_nano_version_max,
          { "Maximum Version", "nano.version_max",
            FT_UINT8, BASE_DEC_HEX, NULL, 0x00,
            "Maximum Supported Protocol Version", HFILL }
        },
        { &hf_nano_version_using,
          { "Using Version", "nano.version_using",
            FT_UINT8, BASE_DEC_HEX, NULL, 0x00,
            "Used Protocol Version", HFILL }
        },
        { &hf_nano_version_min,
          { "Minimum Version", "nano.version_min",
            FT_UINT8, BASE_DEC_HEX, NULL, 0x00,
            "Minimum Supported Protocol Version", HFILL }
        },
        { &hf_nano_packet_type,
          { "Packet Type", "nano.packet_type",
            FT_UINT8, BASE_DEC_HEX, VALS(nano_packet_type_strings), 0x00,
            NULL, HFILL }
        },
        { &hf_nano_extensions,
          { "Extensions Field", "nano.extensions",
            FT_UINT16, BASE_HEX, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_nano_extensions_block_type,
          { "Block Type", "nano.extensions.block_type",
            FT_UINT16, BASE_HEX, VALS(nano_block_type_strings), 0x0f00,
            NULL, HFILL }
        },
        { &hf_nano_keepalive_peer_ip,
          { "Peer IP Address", "nano.keepalive.peer_ip",
            FT_IPv6, BASE_NONE, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_nano_keepalive_peer_port,
          { "Peer Port", "nano.keepalive.peer_port",
            FT_UINT16, BASE_DEC, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_nano_block_hash_previous,
          { "Previous Block Hash", "nano.block.hash_previous",
            FT_BYTES, BASE_NONE, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_nano_block_hash_source,
          { "Source Block Hash", "nano.block.hash_source",
            FT_BYTES, BASE_NONE, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_nano_block_signature,
          { "Signature", "nano.block.signature",
            FT_BYTES, BASE_NONE, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_nano_block_work,
          { "Work", "nano.block.work",
            FT_BYTES, BASE_NONE, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_nano_block_destination_account,
          { "Destination Account", "nano.block.destination_account",
            FT_BYTES, BASE_NONE, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_nano_block_balance,
          { "Balance", "nano.block.balance",
            FT_BYTES, BASE_NONE, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_nano_block_account,
          { "Account", "nano.block.account",
            FT_BYTES, BASE_NONE, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_nano_block_representative_account,
          { "Representative Account", "nano.block.representative_account",
            FT_BYTES, BASE_NONE, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_nano_block_link,
          { "Link", "nano.block.link",
            FT_BYTES, BASE_NONE, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_nano_vote_account,
          { "Account", "nano.vote.account",
            FT_BYTES, BASE_NONE, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_nano_vote_signature,
          { "Signature", "nano.vote.signature",
            FT_BYTES, BASE_NONE, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_nano_vote_sequence,
          { "Sequence", "nano.vote.sequence",
            FT_UINT64, BASE_DEC_HEX, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_nano_bulk_pull_account,
          { "Account", "nano.bulk_pull.account",
            FT_BYTES, BASE_NONE, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_nano_bulk_pull_block_hash_end,
          { "End Block Hash", "nano.bulk_pull_block.hash_end",
            FT_BYTES, BASE_NONE, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_nano_frontier_req_account,
          { "Account", "nano.frontier_req.account",
            FT_BYTES, BASE_NONE, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_nano_frontier_req_age,
          { "Age", "nano.frontier_req.age",
            FT_UINT32, BASE_HEX_DEC, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_nano_frontier_req_count,
          { "Count", "nano.frontier_req.count",
            FT_UINT32, BASE_HEX_DEC, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_nano_bulk_pull_blocks_min_hash,
          { "Min Block Hash", "nano.bulk_pull_blocks.min_hash",
            FT_BYTES, BASE_NONE, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_nano_bulk_pull_blocks_max_hash,
          { "Max Block Hash", "nano.bulk_pull_blocks.max_hash",
            FT_BYTES, BASE_NONE, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_nano_bulk_pull_blocks_mode,
          { "Mode", "nano.bulk_pull_blocks.mode",
            FT_UINT8, BASE_DEC_HEX, VALS(nano_bulk_pull_blocks_mode_strings), 0x00,
            NULL, HFILL }
        },
        { &hf_nano_bulk_pull_blocks_max_count,
          { "Max Count", "nano.bulk_pull_blocks.max_count",
            FT_UINT32, BASE_HEX_DEC, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_nano_bulk_push_block_type,
          { "Block Type", "nano.bulk_push.block_type",
            FT_UINT8, BASE_HEX, VALS(nano_block_type_strings), 0x00,
            NULL, HFILL }
        },
        { &hf_nano_bulk_pull_block_type,
          { "Block Type", "nano.bulk_pull.block_type",
            FT_UINT8, BASE_HEX, VALS(nano_block_type_strings), 0x00,
            NULL, HFILL }
        },
        { &hf_nano_frontier_account,
          { "Account", "nano.frontier.account",
            FT_BYTES, BASE_NONE, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_nano_frontier_head_hash,
          { "Head Hash", "nano.frontier.head_hash",
            FT_BYTES, BASE_NONE, NULL, 0x00,
            NULL, HFILL }
        }
    };

    static gint *ett[] = {
        &ett_nano,
        &ett_nano_header,
        &ett_nano_extensions,
        &ett_nano_peers,
        &ett_nano_peer_details[0],
        &ett_nano_peer_details[1],
        &ett_nano_peer_details[2],
        &ett_nano_peer_details[3],
        &ett_nano_peer_details[4],
        &ett_nano_peer_details[5],
        &ett_nano_peer_details[6],
        &ett_nano_peer_details[7],
        &ett_nano_block,
        &ett_nano_vote,
        &ett_nano_bulk_pull,
        &ett_nano_frontier_req,
        &ett_nano_bulk_pull_blocks,
        &ett_nano_frontier
    };

    proto_nano = proto_register_protocol("Nano Cryptocurrency Protocol", "Nano", "nano");

    proto_register_field_array(proto_nano, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
}

void proto_reg_handoff_nano(void)
{
    nano_handle = register_dissector("nano", dissect_nano, proto_nano);
    dissector_add_uint_with_preference("udp.port", NANO_UDP_PORT, nano_handle);
    heur_dissector_add("udp", dissect_nano_heur_udp, "Nano UDP Heuristics", "nano-udp", proto_nano, HEURISTIC_DISABLE);

    nano_tcp_handle = register_dissector("nano-over-tcp", dissect_nano_tcp, proto_nano);
    dissector_add_uint_with_preference("tcp.port", NANO_TCP_PORT, nano_tcp_handle);
    heur_dissector_add("tcp", dissect_nano_heur_tcp, "Nano TCP Heuristics", "nano-tcp", proto_nano, HEURISTIC_DISABLE);
}

/*
 * Editor modelines  -  https://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 4
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * vi: set shiftwidth=4 tabstop=8 expandtab:
 * :indentSize=4:tabSize=8:noTabs=true:
 */
