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

#include <epan/packet.h>
#include <epan/to_str.h>
#include <wsutil/str_util.h>

void proto_reg_handoff_nano(void);
void proto_register_nano(void);

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

static int hf_nano_vote_account = -1;
static int hf_nano_vote_signature = -1;
static int hf_nano_vote_sequence = -1;

static gint ett_nano = -1;
static gint ett_nano_extensions = -1;
static gint ett_nano_peers = -1;
static gint ett_nano_peer_details[8] = {-1, -1, -1, -1, -1, -1, -1, -1};
static gint ett_nano_block = -1;
static gint ett_nano_vote = -1;


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

static const value_string nano_block_type_strings[] = {
  { NANO_BLOCK_TYPE_INVALID, "Invalid" },
  { NANO_BLOCK_TYPE_NOT_A_BLOCK, "Not A Block" },
  { NANO_BLOCK_TYPE_SEND, "Send" },
  { NANO_BLOCK_TYPE_RECEIVE, "Receive" },
  { NANO_BLOCK_TYPE_OPEN, "Open" },
  { NANO_BLOCK_TYPE_CHANGE, "Change" },
  { 0, NULL },
};

static const string_string nano_magic_numbers[] = {
    { "RA", "Nano Test Network" },
    { "RB", "Nano Beta Network" },
    { "RC", "Nano Production Network" },
    { 0, NULL }
};

#define NANO_UDP_PORT 7075 /* Not IANA registered */


/* Minimum length. If data is received with fewer than this many bytes it is rejected by
 * the current dissector. */
#define NANO_MIN_LENGTH 8


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

    block_tree = proto_tree_add_subtree(nano_tree, tvb, offset, 32+32+64+8, ett_nano_block, NULL, "Receive Block");

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

    block_tree = proto_tree_add_subtree(nano_tree, tvb, offset, 32+32+16+64+8, ett_nano_block, NULL, "Send Block");

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

    block_tree = proto_tree_add_subtree(nano_tree, tvb, offset, 32+32+32+64+8, ett_nano_block, NULL, "Open Block");

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

    block_tree = proto_tree_add_subtree(nano_tree, tvb, offset, 32+32+64+8, ett_nano_block, NULL, "Change Block");

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

/* Code to actually dissect the packets */
static int dissect_nano(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    proto_item *ti;
    proto_tree *nano_tree;
    char *nano_magic_number;
    guint nano_packet_type, nano_block_type, offset;
    guint64 extensions;
    static const int *nano_extensions[] = {
        &hf_nano_extensions_block_type,
        NULL
    };

    /* Check that the packet is long enough for it to belong to us. */
    if (tvb_reported_length(tvb) < NANO_MIN_LENGTH)
        return 0;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "Nano");
    col_clear(pinfo->cinfo, COL_INFO);

    ti = proto_tree_add_item(tree, proto_nano, tvb, 0, -1, ENC_NA);
    nano_tree = proto_item_add_subtree(ti, ett_nano);

    nano_magic_number = tvb_get_string_enc(wmem_packet_scope(), tvb, 0, 2, ENC_ASCII);
    proto_tree_add_string_format_value(nano_tree, hf_nano_magic_number, tvb, 0,
            2, nano_magic_number, "%s (%s)", str_to_str(nano_magic_number, nano_magic_numbers, "Unknown"), nano_magic_number);

    proto_tree_add_item(nano_tree, hf_nano_version_max, tvb, 2, 1, ENC_NA);
    proto_tree_add_item(nano_tree, hf_nano_version_using, tvb, 3, 1, ENC_NA);
    proto_tree_add_item(nano_tree, hf_nano_version_min, tvb, 4, 1, ENC_NA);
    proto_tree_add_item_ret_uint(nano_tree, hf_nano_packet_type, tvb, 5, 1, ENC_NA, &nano_packet_type);

    proto_tree_add_bitmask_ret_uint64(nano_tree, tvb, 6, hf_nano_extensions, ett_nano_extensions, nano_extensions, ENC_LITTLE_ENDIAN, &extensions);

    // call specific dissectors for specific packet types
    offset = 8;
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
            }
            break;

        default:
            col_add_str(pinfo->cinfo, COL_INFO,
                    val_to_str(nano_packet_type, VALS(nano_packet_type_strings), "Unknown (%d)"));
    }

    return tvb_captured_length(tvb);
}

void proto_register_nano(void)
{
    static hf_register_info hf[] = {
        { &hf_nano_magic_number,
          { "Magic Number", "nano.magic_number",
            FT_STRING, STR_ASCII, NULL, 0x00,
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
          { "Peer IP Address", "nano.keepalive_peer_ip",
            FT_IPv6, BASE_NONE, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_nano_keepalive_peer_port,
          { "Peer Port", "nano.keepalive_peer_port",
            FT_UINT16, BASE_DEC, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_nano_block_hash_previous,
          { "Previous Block Hash", "nano.block_hash_previous",
            FT_BYTES, BASE_NONE, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_nano_block_hash_source,
          { "Source Block Hash", "nano.block_hash_source",
            FT_BYTES, BASE_NONE, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_nano_block_signature,
          { "Signature", "nano.block_signature",
            FT_BYTES, BASE_NONE, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_nano_block_work,
          { "Work", "nano.block_work",
            FT_BYTES, BASE_NONE, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_nano_block_destination_account,
          { "Destination Account", "nano.block_destination_account",
            FT_BYTES, BASE_NONE, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_nano_block_balance,
          { "Balance", "nano.block_balance",
            FT_BYTES, BASE_NONE, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_nano_block_account,
          { "Account", "nano.block_account",
            FT_BYTES, BASE_NONE, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_nano_block_representative_account,
          { "Representative Account", "nano.block_representative_account",
            FT_BYTES, BASE_NONE, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_nano_vote_account,
          { "Account", "nano.vote_account",
            FT_BYTES, BASE_NONE, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_nano_vote_signature,
          { "Signature", "nano.vote_signature",
            FT_BYTES, BASE_NONE, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_nano_vote_sequence,
          { "Sequence", "nano.vote_sequence",
            FT_UINT64, BASE_DEC_HEX, NULL, 0x00,
            NULL, HFILL }
        }
    };

    static gint *ett[] = {
        &ett_nano,
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
        &ett_nano_vote
    };

    proto_nano = proto_register_protocol("Nano Cryptocurrency Protocol", "Nano", "nano");

    proto_register_field_array(proto_nano, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
}

void proto_reg_handoff_nano(void)
{
    dissector_handle_t nano_handle;

    nano_handle = create_dissector_handle(dissect_nano, proto_nano);
    dissector_add_uint_with_preference("udp.port", NANO_UDP_PORT, nano_handle);
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
