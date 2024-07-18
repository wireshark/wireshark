/*
 * packet-raknet.c
 *
 * Routines for RakNet protocol packet disassembly.
 *
 * Ref: https://github.com/OculusVR/RakNet
 *
 * Nick Carter <ncarter100@gmail.com>
 * Copyright 2014 Nick Carter
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#include "config.h"

#include <epan/conversation.h>
#include <epan/exceptions.h>
#include <epan/expert.h>
#include <epan/packet.h>
#include <epan/reassemble.h>
#include <epan/to_str.h>
#include <epan/wmem_scopes.h>

#include "packet-raknet.h"

/*
 * RakNet Protocol Constants.
 */
static uint8_t RAKNET_OFFLINE_MESSAGE_DATA_ID[16] = {0x00, 0xff, 0xff, 0x00, 0xfe, 0xfe, 0xfe, 0xfe, 0xfd, 0xfd, 0xfd, 0xfd, 0x12, 0x34, 0x56, 0x78};
#define RAKNET_CHALLENGE_LENGTH 64
#define RAKNET_ANSWER_LENGTH 128
#define RAKNET_PROOF_LENGTH 32
#define RAKNET_IDENTITY_LENGTH 160
#define RAKNET_NUMBER_OF_INTERNAL_IDS 10

static int proto_raknet;
static int ett_raknet; /* Should this node be expanded */
static int ett_raknet_system_address;
static int ett_raknet_packet_type;
static int ett_raknet_packet_number_range;
static int ett_raknet_message;
static int ett_raknet_message_flags;
static int ett_raknet_system_message;

/*
 * Dissectors
 */
static dissector_handle_t raknet_handle;
static dissector_table_t raknet_offline_message_dissectors;
static dissector_table_t raknet_system_message_dissectors;
static dissector_table_t raknet_port_dissectors;
static heur_dissector_list_t raknet_heur_subdissectors;

/*
 * Expert fields
 */
static expert_field ei_raknet_unknown_message_id;
static expert_field ei_raknet_encrypted_message;
static expert_field ei_raknet_subdissector_failed;
static expert_field ei_raknet_ip_ver_invalid;

/*
 * First byte gives us the packet id
 */
static int hf_raknet_offline_message_id;

/*
 * General fields (fields that are in >1 packet types.
 */
static int hf_raknet_client_guid;
static int hf_raknet_timestamp;
static int hf_raknet_offline_message_data_id;
static int hf_raknet_mtu_size;
static int hf_raknet_raknet_proto_ver;
static int hf_raknet_server_guid;
static int hf_raknet_ip_version;
static int hf_raknet_ipv4_address;
static int hf_raknet_ipv6_address;
static int hf_raknet_port;

/*
 * Fields specific to a packet id type
 */
static int hf_raknet_null_padding;
static int hf_raknet_use_encryption;
static int hf_raknet_server_public_key;
static int hf_raknet_cookie;
static int hf_raknet_client_wrote_challenge;
static int hf_raknet_client_challenge;
static int hf_raknet_client_address;
static int hf_raknet_server_address;
static int hf_raknet_server_answer;
static int hf_raknet_0x1C_server_id_str_len;
static int hf_raknet_0x1C_server_id_str;
static int hf_raknet_packet_type;
static int hf_raknet_packet_is_for_connected;
static int hf_raknet_packet_is_ACK;
static int hf_raknet_packet_has_B_and_AS;
static int hf_raknet_packet_is_NAK;
static int hf_raknet_packet_is_pair;
static int hf_raknet_packet_is_continuous_send;
static int hf_raknet_packet_needs_B_and_AS;
static int hf_raknet_AS;
static int hf_raknet_NACK_record_count;
static int hf_raknet_packet_number_range;
static int hf_raknet_range_max_equal_to_min;
static int hf_raknet_packet_number_min;
static int hf_raknet_packet_number_max;
static int hf_raknet_packet_number;
static int hf_raknet_message;
static int hf_raknet_message_flags;
static int hf_raknet_message_reliability;
static int hf_raknet_message_has_split_packet;
static int hf_raknet_payload_length;
static int hf_raknet_reliable_message_number;
static int hf_raknet_message_sequencing_index;
static int hf_raknet_message_ordering_index;
static int hf_raknet_message_ordering_channel;
static int hf_raknet_split_packet_count;
static int hf_raknet_split_packet_id;
static int hf_raknet_split_packet_index;
static int hf_raknet_split_packet;
static int hf_raknet_system_message;
static int hf_raknet_system_message_id;
static int hf_raknet_client_proof;
static int hf_raknet_use_client_key;
static int hf_raknet_client_identity;
static int hf_raknet_password;
static int hf_raknet_system_index;
static int hf_raknet_internal_address;

/*
 * Frame reassembly
 */
static reassembly_table raknet_reassembly_table;

static int ett_raknet_fragment;
static int ett_raknet_fragments;
static int hf_raknet_fragment;
static int hf_raknet_fragment_count;
static int hf_raknet_fragment_error;
static int hf_raknet_fragment_multiple_tails;
static int hf_raknet_fragment_overlap;
static int hf_raknet_fragment_overlap_conflicts;
static int hf_raknet_fragment_too_long_fragment;
static int hf_raknet_fragments;
static int hf_raknet_reassembled_in;
static int hf_raknet_reassembled_length;

static const fragment_items raknet_frag_items = {
    /* Fragment subtrees */
    &ett_raknet_fragment,
    &ett_raknet_fragments,
    /* Fragment fields */
    &hf_raknet_fragments,
    &hf_raknet_fragment,
    &hf_raknet_fragment_overlap,
    &hf_raknet_fragment_overlap_conflicts,
    &hf_raknet_fragment_multiple_tails,
    &hf_raknet_fragment_too_long_fragment,
    &hf_raknet_fragment_error,
    &hf_raknet_fragment_count,
    /* Reassembled in field */
    &hf_raknet_reassembled_in,
    /* Reassembled length field */
    &hf_raknet_reassembled_length,
    /* Reassembled data field */
    NULL,
    /* Tag */
    "Message fragments"
};

/*
 * Session state
 */
typedef struct raknet_session_state {
    bool use_encryption;
    dissector_handle_t subdissector;
} raknet_session_state_t;

/*
 * Reliability strings
 * Ref: ..RakNet/Source/PacketPriority.h
 *
 * Note that ACK receipts will not be transmitted to the wire. See
 * ReliabilityLayer::WriteToBitStreamFromInternalPacket()
 */
#define raknet_reliability_VALUE_STRING_LIST(VS)                 \
    VS( RAKNET_UNRELIABLE          , 0, "unreliable"           ) \
    VS( RAKNET_UNRELIABLE_SEQUENCED, 1, "unreliable sequenced" ) \
    VS( RAKNET_RELIABLE            , 2, "reliable"             ) \
    VS( RAKNET_RELIABLE_ORDERED    , 3, "reliable ordered"     ) \
    VS( RAKNET_RELIABLE_SEQUENCED  , 4, "reliable sequenced"   )

typedef VALUE_STRING_ENUM(raknet_reliability) raknet_reliability_t;
VALUE_STRING_ARRAY(raknet_reliability);

/*
 * Forward declarations.
 */
void proto_register_raknet(void);
void proto_reg_handoff_raknet(void);
static proto_tree *init_raknet_offline_message(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int *offset);


/*
 * Called by dissectors for protocols that run atop RakNet/UDP.
 */
void
raknet_add_udp_dissector(uint32_t port, const dissector_handle_t handle) {
    /*
     * Register ourselves as the handler for that port number
     * over TCP.
     */
    dissector_add_uint("udp.port", port, raknet_handle);

    /*
     * And register them in *our* table for that port.
     */
    dissector_add_uint("raknet.port", port, handle);
}

void
raknet_delete_udp_dissector(uint32_t port, const dissector_handle_t handle) {
    dissector_delete_uint("udp.port", port, raknet_handle);
    dissector_delete_uint("raknet.port", port, handle);
}

static raknet_session_state_t*
raknet_get_session_state(packet_info *pinfo) {
    conversation_t* conversation;
    raknet_session_state_t* state;

    conversation = find_or_create_conversation(pinfo);
    state = (raknet_session_state_t*)conversation_get_proto_data(conversation, proto_raknet);

    if (state == NULL) {
        state = wmem_new(wmem_file_scope(), raknet_session_state_t);
        state->use_encryption = false;
        state->subdissector = NULL;
        conversation_add_proto_data(conversation, proto_raknet, state);
    }

    return state;
}

void
raknet_conversation_set_dissector(packet_info *pinfo, const dissector_handle_t handle) {
    raknet_session_state_t *state;

    state = raknet_get_session_state(pinfo);
    state->subdissector = handle;
}

static void
raknet_dissect_system_address(proto_tree *tree, int hf,
        packet_info *pinfo, tvbuff_t *tvb, int *offset) {
    proto_item *ti;
    proto_tree *sub_tree;
    uint8_t ip_version;
    uint32_t v4_addr;
    uint16_t port;
    address addr;
    char *addr_str;

    /* XXX - does it really make sense to have a string hf that's set to
       an empty string? */
    ti = proto_tree_add_string(tree, hf, tvb, *offset, -1, "");
    sub_tree = proto_item_add_subtree(ti, ett_raknet_system_address);
    ip_version = tvb_get_uint8(tvb, *offset);
    proto_tree_add_item(sub_tree, hf_raknet_ip_version, tvb, *offset, 1, ENC_NA);
    (*offset)++;
    switch (ip_version) {
    case 4:
        /*
         * IPv4 addresses are bit-inverted to prevent routers from
         * changing them. See ..RakNet/Source/BitStream.h
         * (BitStream::Write)
         */
        v4_addr = ~tvb_get_ipv4(tvb, *offset);
        set_address(&addr, AT_IPv4, sizeof(v4_addr), &v4_addr);
        addr_str = address_to_display(pinfo->pool, &addr);
        proto_tree_add_ipv4(sub_tree, hf_raknet_ipv4_address, tvb, *offset, 4, v4_addr);
        *offset += 4;
        port = tvb_get_ntohs(tvb, *offset);
        proto_tree_add_item(sub_tree, hf_raknet_port, tvb, *offset, 2, ENC_BIG_ENDIAN);
        *offset += 2;
        proto_item_set_len(ti, 1 + 4 + 2);
        proto_item_append_text(ti, "%s:%" PRIu16, addr_str, port);
        break;
    case 6:
        addr_str = tvb_ip6_to_str(pinfo->pool, tvb, *offset);
        proto_tree_add_item(sub_tree, hf_raknet_ipv6_address, tvb, *offset, 16, ENC_NA);
        *offset += 16;
        port = tvb_get_ntohs(tvb, *offset);
        proto_tree_add_item(sub_tree, hf_raknet_port, tvb, *offset, 2, ENC_BIG_ENDIAN);
        *offset += 2;
        proto_item_set_len(ti, 1 + 16 + 2);
        proto_item_append_text(ti, "[%s]:%" PRIu16, addr_str, port);
        break;
    default:
        proto_item_set_len(ti, 1);
        expert_add_info(pinfo, sub_tree, &ei_raknet_ip_ver_invalid);
    }
}

static int
raknet_dissect_unconnected_ping(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                                void *data _U_)
{
    proto_tree *sub_tree;
    int offset;

    sub_tree = init_raknet_offline_message(tvb, pinfo, tree, &offset);

    proto_tree_add_item(sub_tree, hf_raknet_timestamp, tvb,
                        offset, 8, ENC_BIG_ENDIAN);
    offset += 8;

    proto_tree_add_item(sub_tree, hf_raknet_offline_message_data_id, tvb, offset,
                        16, ENC_NA);
    offset += 16;

    proto_tree_add_item(sub_tree, hf_raknet_client_guid, tvb,
                        offset, 8, ENC_NA);
    offset += 8;

    return offset;
}

static int
raknet_dissect_open_connection_request_1(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                                         void *data _U_)
{
    proto_tree *sub_tree;
    int offset;

    sub_tree = init_raknet_offline_message(tvb, pinfo, tree, &offset);

    proto_tree_add_item(sub_tree, hf_raknet_offline_message_data_id, tvb, offset,
                        16, ENC_NA);
    offset += 16;

    proto_tree_add_item(sub_tree, hf_raknet_raknet_proto_ver, tvb, offset,
                        1, ENC_BIG_ENDIAN);
    offset += 1;

    /* -1 read to end of tvb buffer */
    proto_tree_add_item(sub_tree, hf_raknet_null_padding, tvb, offset,
                        -1, ENC_NA);

    return tvb_reported_length(tvb);
}

static int
raknet_dissect_open_connection_reply_1(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                                       void *data _U_)
{
    proto_tree *sub_tree;
    int offset;
    raknet_session_state_t* state;

    sub_tree = init_raknet_offline_message(tvb, pinfo, tree, &offset);


    proto_tree_add_item(sub_tree, hf_raknet_offline_message_data_id, tvb, offset,
                        16, ENC_NA);
    offset += 16;

    proto_tree_add_item(sub_tree, hf_raknet_server_guid, tvb, offset,
                        8, ENC_NA);
    offset += 8;

    state = raknet_get_session_state(pinfo);
    state->use_encryption = tvb_get_uint8(tvb, offset) ? true : false;

    proto_tree_add_item(sub_tree, hf_raknet_use_encryption, tvb,
                        offset, 1, ENC_NA);
    offset += 1;

    if (state->use_encryption) {
        proto_tree_add_item(sub_tree, hf_raknet_cookie, tvb,
                            offset, 4, ENC_BIG_ENDIAN);
        offset += 4;

        proto_tree_add_item(sub_tree, hf_raknet_server_public_key, tvb,
                            offset, 64, ENC_NA);
        offset += 64;
    }

    proto_tree_add_item(sub_tree, hf_raknet_mtu_size, tvb, offset,
                        2, ENC_BIG_ENDIAN);
    offset += 2;

    return offset;
}

static int
raknet_dissect_open_connection_request_2(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                                         void *data _U_)
{
    proto_tree *sub_tree;
    int offset;
    raknet_session_state_t* state;

    sub_tree = init_raknet_offline_message(tvb, pinfo, tree, &offset);

    proto_tree_add_item(sub_tree, hf_raknet_offline_message_data_id, tvb, offset,
                        16, ENC_NA);
    offset += 16;

    state = raknet_get_session_state(pinfo);
    if (state->use_encryption) {
        bool client_wrote_challenge;

        proto_tree_add_item(sub_tree, hf_raknet_cookie, tvb, offset,
                            4, ENC_BIG_ENDIAN);
        offset += 4;

        client_wrote_challenge = tvb_get_uint8(tvb, offset) ? true : false;
        proto_tree_add_item(sub_tree, hf_raknet_client_wrote_challenge, tvb, offset,
                            1, ENC_NA);
        offset += 1;

        if (client_wrote_challenge) {
            proto_tree_add_item(sub_tree, hf_raknet_client_challenge, tvb,
                                offset, 64, ENC_NA);
            offset += 64;
        }
    }

    raknet_dissect_system_address(
            sub_tree, hf_raknet_server_address, pinfo, tvb, &offset);

    proto_tree_add_item(sub_tree, hf_raknet_mtu_size, tvb, offset,
                        2, ENC_BIG_ENDIAN);
    offset += 2;

    proto_tree_add_item(sub_tree, hf_raknet_client_guid, tvb, offset,
                        8, ENC_NA);
    offset += 8;

    return offset;
}

static int
raknet_dissect_open_connection_reply_2(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                                       void *data _U_)
{
    proto_tree *sub_tree;
    int offset;
    raknet_session_state_t* state;

    sub_tree = init_raknet_offline_message(tvb, pinfo, tree, &offset);

    proto_tree_add_item(sub_tree, hf_raknet_offline_message_data_id, tvb, offset,
                        16, ENC_NA);
    offset += 16;

    proto_tree_add_item(sub_tree, hf_raknet_server_guid, tvb, offset,
                        8, ENC_NA);
    offset += 8;

    raknet_dissect_system_address(
            sub_tree, hf_raknet_client_address, pinfo, tvb, &offset);

    proto_tree_add_item(sub_tree, hf_raknet_mtu_size, tvb, offset,
                        2, ENC_BIG_ENDIAN);
    offset += 2;

    state = raknet_get_session_state(pinfo);
    state->use_encryption = tvb_get_uint8(tvb, offset) ? true : false;

    proto_tree_add_item(sub_tree, hf_raknet_use_encryption, tvb, offset,
                        1, ENC_NA);
    offset += 1;

    if (state->use_encryption) {
        proto_tree_add_item(sub_tree, hf_raknet_server_answer, tvb, offset,
                            128, ENC_NA);
        offset += 128;
    }

    return offset;
}

static int
raknet_dissect_incompatible_protocol_version(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                                             void *data _U_)
{
    proto_tree *sub_tree;
    int offset;

    sub_tree = init_raknet_offline_message(tvb, pinfo, tree, &offset);

    proto_tree_add_item(sub_tree, hf_raknet_raknet_proto_ver, tvb,
                        offset, 1, ENC_BIG_ENDIAN);
    offset += 1;

    proto_tree_add_item(sub_tree, hf_raknet_offline_message_data_id, tvb, offset,
                        16, ENC_NA);
    offset += 16;

    proto_tree_add_item(sub_tree, hf_raknet_server_guid, tvb, offset,
                        8, ENC_NA);
    offset += 8;

    return offset;
}

static int
raknet_dissect_connection_failed(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                                 void *data _U_)
{
    proto_tree *sub_tree;
    int offset;

    sub_tree = init_raknet_offline_message(tvb, pinfo, tree, &offset);

    proto_tree_add_item(sub_tree, hf_raknet_offline_message_data_id, tvb, offset,
                        16, ENC_NA);
    offset += 16;

    proto_tree_add_item(sub_tree, hf_raknet_server_guid, tvb, offset,
                        8, ENC_NA);
    offset += 8;

    return offset;
}

static int
raknet_dissect_unconnected_pong(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                                void *data _U_)
{
    proto_tree *sub_tree;
    uint32_t str_size;
    int offset;

    sub_tree = init_raknet_offline_message(tvb, pinfo, tree, &offset);

    proto_tree_add_item(sub_tree, hf_raknet_timestamp, tvb,
                        offset, 8, ENC_BIG_ENDIAN);
    offset += 8;

    proto_tree_add_item(sub_tree, hf_raknet_server_guid, tvb, offset,
                        8, ENC_NA);
    offset += 8;

    proto_tree_add_item(sub_tree, hf_raknet_offline_message_data_id, tvb, offset,
                        16, ENC_NA);
    offset += 16;

    /* raknet precedes strings with a short (2 bytes) holding string length. */
    proto_tree_add_item_ret_uint(sub_tree, hf_raknet_0x1C_server_id_str_len, tvb,
                                 offset, 2, ENC_BIG_ENDIAN, &str_size);
    offset += 2;

    proto_tree_add_item(sub_tree, hf_raknet_0x1C_server_id_str, tvb, offset,
                        str_size, ENC_NA|ENC_ASCII);
    offset += str_size;

    return offset;
}

static int
raknet_dissect_connected_ping(tvbuff_t *tvb, packet_info *pinfo _U_,
                              proto_tree *tree, void* data _U_)
{

    int offset = 1;

    proto_tree_add_item(tree, hf_raknet_timestamp, tvb,
                        offset, 8, ENC_BIG_ENDIAN);
    offset += 8;

    return offset;
}

static int
raknet_dissect_connected_pong(tvbuff_t *tvb, packet_info *pinfo _U_,
                              proto_tree *tree, void* data _U_)
{
    int offset = 1;

    proto_tree_add_item(tree, hf_raknet_timestamp, tvb,
                        offset, 8, ENC_BIG_ENDIAN);
    offset += 8;

    proto_tree_add_item(tree, hf_raknet_timestamp, tvb,
                        offset, 8, ENC_BIG_ENDIAN);
    offset += 8;

    return offset;
}

static int
raknet_dissect_connection_request(tvbuff_t *tvb, packet_info *pinfo _U_,
                                  proto_tree *tree, void* data _U_)
{
    int offset = 1;
    bool use_encryption;

    proto_tree_add_item(tree, hf_raknet_client_guid, tvb, offset,
                        8, ENC_NA);
    offset += 8;

    proto_tree_add_item(tree, hf_raknet_timestamp, tvb,
                        offset, 8, ENC_BIG_ENDIAN);
    offset += 8;

    use_encryption = tvb_get_uint8(tvb, offset) ? true : false;

    proto_tree_add_item(tree, hf_raknet_use_encryption, tvb, offset,
                        1, ENC_NA);
    offset += 1;

    if (use_encryption) {
        bool use_client_key;

        proto_tree_add_item(tree, hf_raknet_client_proof, tvb, offset,
                            32, ENC_NA);
        offset += 32;

        use_client_key = tvb_get_uint8(tvb, offset) ? true : false;

        proto_tree_add_item(tree, hf_raknet_use_client_key, tvb, offset,
                            1, ENC_NA);
        offset += 1;

        if (use_client_key) {
            proto_tree_add_item(tree, hf_raknet_client_identity, tvb, offset,
                                160, ENC_NA);
            offset += 160;
        }
    }

    proto_tree_add_item(tree, hf_raknet_password, tvb, offset,
                       -1, ENC_NA);

    return tvb_reported_length(tvb);
}

static int
raknet_dissect_connection_request_accepted(tvbuff_t *tvb, packet_info *pinfo _U_,
                                           proto_tree *tree, void* data _U_)
{
    int offset = 1;
    int i;

    raknet_dissect_system_address(
            tree, hf_raknet_client_address, pinfo, tvb, &offset);

    proto_tree_add_item(tree, hf_raknet_system_index, tvb, offset,
                        2, ENC_BIG_ENDIAN);
    offset += 2;

    for (i = 0; i < RAKNET_NUMBER_OF_INTERNAL_IDS; i++) {
        raknet_dissect_system_address(
                tree, hf_raknet_internal_address, pinfo, tvb, &offset);
    }

    proto_tree_add_item(tree, hf_raknet_timestamp, tvb,
                        offset, 8, ENC_BIG_ENDIAN);
    offset += 8;

    proto_tree_add_item(tree, hf_raknet_timestamp, tvb,
                        offset, 8, ENC_BIG_ENDIAN);
    offset += 8;

    return offset;
}

static int
raknet_dissect_new_incoming_connection(tvbuff_t *tvb, packet_info *pinfo,
                                       proto_tree *tree, void* data _U_)
{

    int offset = 1;
    int i;

    raknet_dissect_system_address(
            tree, hf_raknet_server_address, pinfo, tvb, &offset);

    for (i = 0; i < RAKNET_NUMBER_OF_INTERNAL_IDS; i++) {
        raknet_dissect_system_address(
                tree, hf_raknet_internal_address, pinfo, tvb, &offset);
    }

    proto_tree_add_item(tree, hf_raknet_timestamp, tvb,
                        offset, 8, ENC_BIG_ENDIAN);
    offset += 8;

    proto_tree_add_item(tree, hf_raknet_timestamp, tvb,
                        offset, 8, ENC_BIG_ENDIAN);
    offset += 8;


    return offset;
}

/*
 * Protocol definition and handlers.
 */
struct raknet_handler_entry {
    value_string vs;
    dissector_t dissector_fp;
};

static const struct raknet_handler_entry raknet_offline_message_handlers[] = {
    /*
     * Ref: ..RakNet/Source/MessageIdentifiers.h
     * Ref: ..RakNet/Source/RakPeer.cpp (ProcessOfflineNetworkPacket)
     */
    { { 0x1, "Unconnected Ping" },
        raknet_dissect_unconnected_ping },
    { { 0x2, "Unconnected Ping Open Connections" },
        raknet_dissect_unconnected_ping },
    { { 0x5, "Open Connection Request 1" },
        raknet_dissect_open_connection_request_1 },
    { { 0x6, "Open Connection Reply 1" },
        raknet_dissect_open_connection_reply_1 },
    { { 0x7, "Open Connection Request 2" },
        raknet_dissect_open_connection_request_2 },
    { { 0x8, "Open Connection Reply 2" },
        raknet_dissect_open_connection_reply_2 },
    { { 0xD, "Out Of Band Internal" },
        raknet_dissect_connection_failed },
    { { 0x11, "Connection Attempt Failed" },
        raknet_dissect_connection_failed },
    { { 0x12, "Already Connected" },
        raknet_dissect_connection_failed },
    { { 0x14, "No Free Incoming Connections" },
        raknet_dissect_connection_failed },
    { { 0x17, "Connection Banned" },
        raknet_dissect_connection_failed },
    { { 0x19, "Incompatible Protocol Version" },
        raknet_dissect_incompatible_protocol_version },
    { { 0x1A, "IP Recently Connected" },
        raknet_dissect_connection_failed },
    { { 0x1C, "Unconnected Pong" },
        raknet_dissect_unconnected_pong },
};

static const struct raknet_handler_entry raknet_system_message_handlers[] = {
    /*
     * Ref: ..RakNet/Source/MessageIdentifiers.h
     * Ref: ..RakNet/Source/RakPeer.cpp (RakPeer::RunUpdateCycle)
     */
    { { 0x00, "Connected Ping" },
        raknet_dissect_connected_ping },
    { { 0x03, "Connected Pong" },
        raknet_dissect_connected_pong },
    { { 0x09, "Connection Request" },
        raknet_dissect_connection_request },
    { { 0x10, "Connection Request Accepted" },
        raknet_dissect_connection_request_accepted },
    { { 0x13, "New Incoming Connection" },
        raknet_dissect_new_incoming_connection },
};

/*
 * Look up table from message ID to name.
 */
static value_string raknet_offline_message_names[array_length(raknet_offline_message_handlers)+1];
static value_string raknet_system_message_names[array_length(raknet_system_message_handlers)+1];

static void
raknet_init_message_names(void)
{
    unsigned int i;

    for (i = 0; i < array_length(raknet_offline_message_handlers); i++) {
        raknet_offline_message_names[i].value  = raknet_offline_message_handlers[i].vs.value;
        raknet_offline_message_names[i].strptr = raknet_offline_message_handlers[i].vs.strptr;
    }
    raknet_offline_message_names[array_length(raknet_offline_message_handlers)].value  = 0;
    raknet_offline_message_names[array_length(raknet_offline_message_handlers)].strptr = NULL;

    for (i = 0; i < array_length(raknet_system_message_handlers); i++) {
        raknet_system_message_names[i].value  = raknet_system_message_handlers[i].vs.value;
        raknet_system_message_names[i].strptr = raknet_system_message_handlers[i].vs.strptr;
    }
    raknet_system_message_names[array_length(raknet_system_message_handlers)].value  = 0;
    raknet_system_message_names[array_length(raknet_system_message_handlers)].strptr = NULL;
}

/*
 * Fill out the Info column and protocol subtree.
 *
 * Offset is updated for the caller.
 */
static proto_tree *
init_raknet_offline_message(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int *offset)
{
    proto_tree *sub_tree;
    proto_item *ti;
    uint8_t message_id;

    *offset = 0;

    /*
     * Take buffer start 0 to end -1 as single raknet item.
     */
    ti = proto_tree_add_item(tree, proto_raknet, tvb, 0, -1, ENC_NA);
    sub_tree = proto_item_add_subtree(ti, ett_raknet);

    message_id = tvb_get_uint8(tvb, *offset);
    proto_tree_add_item(sub_tree, hf_raknet_offline_message_id, tvb, *offset,
                        1, ENC_BIG_ENDIAN);
    *offset += 1;

    col_add_str(pinfo->cinfo, COL_INFO,
                val_to_str(message_id, raknet_offline_message_names, "Unknown offline message: %#x"));

    /*
     * Append description to the raknet item.
     */
    proto_item_append_text(ti, ", Offline message ID %#x", message_id);

    return sub_tree;
}

static int
raknet_dissect_ACK(tvbuff_t *tvb, packet_info *pinfo,
                   proto_tree *tree, void* data)
{
    int offset = 0;
    proto_tree *sub_tree;
    uint32_t count;
    uint32_t i;

    if (*(bool*)data) {
        col_add_str(pinfo->cinfo, COL_INFO, "ACK");
    }
    else {
        col_add_str(pinfo->cinfo, COL_INFO, "NAK");
    }

    proto_tree_add_item_ret_uint(tree, hf_raknet_NACK_record_count, tvb,
                                 offset, 2, ENC_BIG_ENDIAN, &count);
    offset += 2;

    for (i = 0; i < count; i++) {
        proto_item *ti;
        uint32_t max;
        uint32_t min;

        if (i == 0) {
            col_append_str(pinfo->cinfo, COL_INFO, " ");
        }
        else {
            col_append_str(pinfo->cinfo, COL_INFO, ", ");
        }

        if (tvb_get_uint8(tvb, offset)) { /* maxEqualToMin */
            min = tvb_get_uint24(tvb, offset + 1, ENC_LITTLE_ENDIAN);

            col_append_fstr(pinfo->cinfo, COL_INFO, "#%" PRIu32, min);

            ti = proto_tree_add_string_format_value(tree, hf_raknet_packet_number_range, tvb,
                                                    offset, 1 + 3, "",
                                                    "%" PRIu32 " .. %" PRIu32,
                                                    min, min);
            sub_tree = proto_item_add_subtree(ti, ett_raknet_packet_number_range);

            proto_tree_add_item(sub_tree, hf_raknet_range_max_equal_to_min, tvb,
                                offset, 1, ENC_NA);
            offset += 1;

            proto_tree_add_item(sub_tree, hf_raknet_packet_number_min, tvb,
                                offset, 3, ENC_LITTLE_ENDIAN);
            offset += 3;
        }
        else {
            min = tvb_get_uint24(tvb, offset + 1    , ENC_LITTLE_ENDIAN);
            max = tvb_get_uint24(tvb, offset + 1 + 3, ENC_LITTLE_ENDIAN);

            col_append_fstr(pinfo->cinfo, COL_INFO,
                            "#%" PRIu32 "..%" PRIu32,
                            min, max);

            ti = proto_tree_add_string_format_value(tree, hf_raknet_packet_number_range, tvb,
                                                    offset, 1 + 3 + 3, "",
                                                    "%" PRIu32 " .. %" PRIu32, min, max);
            sub_tree = proto_item_add_subtree(ti, ett_raknet_packet_number_range);

            proto_tree_add_item(sub_tree, hf_raknet_range_max_equal_to_min, tvb,
                                offset, 1, ENC_NA);
            offset += 1;

            proto_tree_add_item(sub_tree, hf_raknet_packet_number_min, tvb,
                                offset, 3, ENC_LITTLE_ENDIAN);
            offset += 3;

            proto_tree_add_item(sub_tree, hf_raknet_packet_number_max, tvb,
                                offset, 3, ENC_LITTLE_ENDIAN);
            offset += 3;
        }
    }

    return tvb_captured_length(tvb);
}

static int
raknet_dissect_common_message(tvbuff_t *tvb, packet_info *pinfo, proto_tree *raknet_tree, void *data)
{
    int offset = 0;
    bool *has_multiple_messages;
    proto_item *ti;
    proto_item *raknet_ti;
    proto_item *msg_ti;
    proto_tree *msg_tree;
    uint64_t msg_flags;
    uint32_t payload_bits;
    uint32_t payload_octets;
    raknet_reliability_t reliability;
    bool has_split_packet;
    uint8_t message_id;
    int message_size;
    proto_tree *payload_tree;
    tvbuff_t* next_tvb;
    bool next_tvb_is_subset;
    dissector_handle_t next_dissector;
    int dissected;
    heur_dtbl_entry_t *hdtbl_entry;
    static int * const flag_flds[] = {
        &hf_raknet_message_reliability,
        &hf_raknet_message_has_split_packet,
        NULL
    };

    has_multiple_messages = (bool*)data;
    raknet_ti = proto_tree_get_parent(raknet_tree);

    msg_ti = proto_tree_add_item(raknet_tree, hf_raknet_message, tvb, offset, -1, ENC_NA);
    msg_tree = proto_item_add_subtree(msg_ti, ett_raknet_message);
    proto_item_append_text(msg_ti, ", ");

    proto_tree_add_bitmask_ret_uint64(msg_tree, tvb, offset, hf_raknet_message_flags,
                                      ett_raknet_message_flags, flag_flds, ENC_NA, &msg_flags);
    offset += 1;

    ti = proto_tree_add_item_ret_uint(msg_tree, hf_raknet_payload_length, tvb,
                                      offset, 2, ENC_BIG_ENDIAN, &payload_bits);
    offset += 2;
    payload_octets = payload_bits / 8 + (payload_bits % 8 > 0); /* ceil(bits / 8) */
    proto_item_append_text(ti, " bits (%" PRIu32 " octets)", payload_octets);

    reliability = (raknet_reliability_t)((msg_flags >> 5) & 0x07);
    has_split_packet = (msg_flags >> 4) & 0x01 ? true : false;

    if (reliability == RAKNET_RELIABLE ||
        reliability == RAKNET_RELIABLE_SEQUENCED ||
        reliability == RAKNET_RELIABLE_ORDERED ) {

        proto_tree_add_item(msg_tree, hf_raknet_reliable_message_number, tvb,
                            offset, 3, ENC_LITTLE_ENDIAN);
        offset += 3;
    }

    if (reliability == RAKNET_UNRELIABLE_SEQUENCED ||
        reliability == RAKNET_RELIABLE_SEQUENCED) {

        proto_tree_add_item(msg_tree, hf_raknet_message_sequencing_index, tvb,
                            offset, 3, ENC_LITTLE_ENDIAN);
        offset += 3;
    }

    if (reliability == RAKNET_UNRELIABLE_SEQUENCED ||
        reliability == RAKNET_RELIABLE_SEQUENCED ||
        reliability == RAKNET_RELIABLE_ORDERED) {

        proto_tree_add_item(msg_tree, hf_raknet_message_ordering_index, tvb,
                            offset, 3, ENC_LITTLE_ENDIAN);
        offset += 3;

        proto_tree_add_item(msg_tree, hf_raknet_message_ordering_channel, tvb,
                            offset, 1, ENC_NA);
        offset += 1;
    }

    if (has_split_packet) {
        bool save_fragmented;
        uint32_t split_packet_count;
        uint32_t split_packet_id;
        uint32_t split_packet_index;
        fragment_head *frag_msg;


        proto_tree_add_item_ret_uint(msg_tree, hf_raknet_split_packet_count, tvb,
                                     offset, 4, ENC_BIG_ENDIAN, &split_packet_count);
        offset += 4;

        proto_tree_add_item_ret_uint(msg_tree, hf_raknet_split_packet_id, tvb,
                                     offset, 2, ENC_BIG_ENDIAN, &split_packet_id);
        offset += 2;

        proto_tree_add_item_ret_uint(msg_tree, hf_raknet_split_packet_index, tvb,
                                     offset, 4, ENC_BIG_ENDIAN, &split_packet_index);
        offset += 4;

        /*
         * Reassemble the fragmented packet.
         */
        save_fragmented = pinfo->fragmented;
        pinfo->fragmented = true;

        frag_msg =
            fragment_add_seq_check(&raknet_reassembly_table,
                                   tvb, offset, pinfo,
                                   split_packet_id,
                                   NULL,
                                   split_packet_index,
                                   payload_octets,
                                   split_packet_index != split_packet_count - 1);

        next_tvb =
            process_reassembled_data(tvb, offset, pinfo, "Reassembled packet",
                                     frag_msg, &raknet_frag_items, NULL, msg_tree);

        pinfo->fragmented = save_fragmented;

        if (next_tvb) {
            /*
             * Reassembly done. Dissect the message as normal.
             */
            wmem_strbuf_t *strbuf;

            strbuf = wmem_strbuf_new(pinfo->pool, "");
            wmem_strbuf_append_printf(strbuf,
                                      "{Message fragment %" PRIu32 "/%" PRIu32 "; Reassembled} ",
                                      split_packet_index + 1, split_packet_count);

            proto_item_append_text(msg_ti, "%s", wmem_strbuf_get_str(strbuf));
            col_add_str(pinfo->cinfo, COL_INFO, wmem_strbuf_get_str(strbuf));
            col_set_fence(pinfo->cinfo, COL_INFO);

            next_tvb_is_subset = false;
        }
        else {
            wmem_strbuf_t *strbuf;

            strbuf = wmem_strbuf_new(pinfo->pool, "");
            wmem_strbuf_append_printf(strbuf,
                                      "{Message fragment %" PRIu32 "/%" PRIu32 "}",
                                      split_packet_index + 1, split_packet_count);

            proto_item_append_text(msg_ti, "%s", wmem_strbuf_get_str(strbuf));
            col_add_str(pinfo->cinfo, COL_INFO, wmem_strbuf_get_str(strbuf));

            ti = proto_tree_add_item(msg_tree, hf_raknet_split_packet, tvb, offset,
                                     payload_octets, ENC_NA);
            proto_item_append_text(ti, " (%u octets)", payload_octets);
        }
    }
    else {
        next_tvb = tvb_new_subset_length(tvb, offset, payload_octets);
        next_tvb_is_subset = true;
    }

    /*
     * At this point we can finally check if the packet has multiple
     * messages.
     */
    if (! *has_multiple_messages) {
        *has_multiple_messages =
            tvb_reported_length_remaining(tvb, offset) > (int)payload_octets
            ? true : false;
    }

    /*
     * And we finally have the actual size of message.
     */
    message_size = offset + payload_octets;

    if (!next_tvb) {
        /*
         * It was an incomplete message fragment.
         */
        proto_item_set_len(msg_ti, message_size);
        if (raknet_ti) {
            proto_item_set_len(raknet_ti, proto_item_get_len(raknet_ti) + message_size);
        }
        return message_size;
    }

    message_id = tvb_get_uint8(next_tvb, 0);

    /*
     * Now we want to dissect this message. First we search for a
     * dissector from our system message dissector table.
     */
    next_dissector =
        dissector_get_uint_handle(raknet_system_message_dissectors, message_id);

    if (next_dissector) {
        /*
         * We have a subdissector. The protocol of the message is
         * still RakNet (e.g. 0x09 ID_CONNECTION_REQUEST) so we always
         * insert it into our tree.
         */
        ti = proto_tree_add_item(msg_tree, hf_raknet_system_message, next_tvb, 0, -1, ENC_NA);
        payload_tree = proto_item_add_subtree(ti, ett_raknet_system_message);

        proto_item_append_text(ti, " (%s)",
                               val_to_str(message_id, raknet_system_message_names, "Unknown ID: %#x"));

        proto_item_append_text(msg_ti, "ID %#x (%s)", message_id,
                               val_to_str_const(message_id, raknet_system_message_names, "Unknown"));

        col_add_str(pinfo->cinfo, COL_INFO,
                    val_to_str(message_id, raknet_system_message_names, "Unknown system message ID: %#x"));

        proto_tree_add_item(payload_tree, hf_raknet_system_message_id,
                            next_tvb, 0, 1, ENC_NA);

        dissected =
            call_dissector_only(next_dissector, next_tvb, pinfo, payload_tree, data);

        proto_item_set_len(msg_ti, message_size);
        if (raknet_ti) {
            proto_item_set_len(raknet_ti, proto_item_get_len(raknet_ti) + message_size);
        }

        if (dissected >= 0) {
            return message_size;
        }
        else {
            return dissected;
        }
    }

    /*
     * It seems not to be a system message so use a dissector set for
     * this conversation if any.
     */
    next_dissector =
        raknet_get_session_state(pinfo)->subdissector;

    /*
     * And of course we don't know the name of message.
     */
    proto_item_append_text(msg_ti, "ID %#x", message_id);

    /*
     * The message belongs to a sub-protocol of RakNet so let it place
     * its own protocol layer, but only if the packet has only one
     * message.
     */
    if (*has_multiple_messages) {
        payload_tree = msg_tree;
    }
    else {
        payload_tree = proto_tree_get_root(raknet_tree);
    }

    if (next_dissector) {
        dissected =
            call_dissector_only(next_dissector, next_tvb, pinfo, payload_tree, data);

        if (dissected > 0) {
            goto FIX_UP_AND_RETURN;
        }
        else {
            expert_add_info(pinfo, msg_tree, &ei_raknet_subdissector_failed);
        }
    }

    /*
     * No dissectors set for this conversation. Look up a dissector
     * from the port table.
     */
    next_dissector =
        dissector_get_uint_handle(raknet_port_dissectors, pinfo->match_uint);

    if (next_dissector) {
        dissected =
            call_dissector_only(next_dissector, next_tvb, pinfo, payload_tree, data);

        if (dissected > 0) {
            goto FIX_UP_AND_RETURN;
        }
        else {
            expert_add_info(pinfo, msg_tree, &ei_raknet_subdissector_failed);
        }
    }

    /*
     * We don't have a subdissector or we have one but id didn't
     * dissect the message. Try heuristic subdissectors.
     */
    dissected =
        dissector_try_heuristic(raknet_heur_subdissectors, next_tvb, pinfo, payload_tree,
                                &hdtbl_entry, data);
    if (!dissected) {
        col_add_fstr(pinfo->cinfo, COL_INFO, "Unknown message ID: %#x", message_id);

        ti = proto_tree_add_expert(msg_tree, pinfo, &ei_raknet_unknown_message_id, next_tvb,
                                   0, 1);
        proto_item_append_text(ti, " %#x", message_id);
    }

  FIX_UP_AND_RETURN:
    /*
     * Fix up the top-level item so that it doesn't include stuff for
     * sub-protocols. In order to do this there must not be multiple
     * messages in the packet, and the message must have been
     * reassembled from fragments.
     */
    if (!*has_multiple_messages && next_tvb_is_subset) {
        proto_item_set_len(msg_ti, message_size - payload_octets);
        if (raknet_ti) {
            proto_item_set_len(raknet_ti, proto_item_get_len(raknet_ti) + message_size - payload_octets);
        }
    }
    else {
        proto_item_set_len(msg_ti, message_size);
        if (raknet_ti) {
            proto_item_set_len(raknet_ti, proto_item_get_len(raknet_ti) + message_size);
        }
    }
    return message_size;
}

static int
raknet_dissect_connected_message(tvbuff_t *tvb, packet_info *pinfo,
                                 proto_tree *root_tree, void* data _U_)
{
    raknet_session_state_t* state;
    proto_item *ti;
    proto_tree *raknet_tree;
    int item_size;
    int offset = 0;
    uint8_t msg_type;

    state = raknet_get_session_state(pinfo);
    if (state->use_encryption) {
        /*
         * RakNet uses ChaCha stream cipher to encrypt messages, which
         * is currently not supported by this dissector.
         */
        col_add_str(pinfo->cinfo, COL_INFO, "Encrypted message");

        item_size = tvb_reported_length_remaining(tvb, offset);
        ti = proto_tree_add_expert(root_tree, pinfo, &ei_raknet_encrypted_message, tvb,
                                   offset, item_size);
        proto_item_append_text(ti, " (%d octets)", item_size);
        return tvb_captured_length(tvb);
    }

    msg_type = tvb_get_uint8(tvb, offset);

    if (!(msg_type & (1 << 7))) { /* !isValid */
        /*
         * No suitable dissector was registered for this offline
         * message.
         */
        col_add_fstr(pinfo->cinfo, COL_INFO, "Unknown offline message ID: %#x", msg_type);
        ti = proto_tree_add_expert(root_tree, pinfo, &ei_raknet_unknown_message_id, tvb,
                                   0, 1);
        proto_item_append_text(ti, " %#x", msg_type);
        return tvb_captured_length(tvb);
    }
    else if (msg_type & (1 << 6)) { /* isACK */
        static int * const ack_flds[] = {
            &hf_raknet_packet_is_for_connected,
            &hf_raknet_packet_is_ACK,
            &hf_raknet_packet_has_B_and_AS,
            NULL
        };

        ti = proto_tree_add_item(root_tree, proto_raknet, tvb, 0, -1, ENC_NA);
        proto_item_append_text(ti, ", ACK");
        raknet_tree = proto_item_add_subtree(ti, ett_raknet);

        proto_tree_add_bitmask(raknet_tree, tvb, offset, hf_raknet_packet_type,
                               ett_raknet_packet_type, ack_flds, ENC_NA);
        offset += 1;

        if (msg_type & (1 << 5)) { /* hasBAndAS */
            proto_tree_add_item(raknet_tree, hf_raknet_AS, tvb, offset,
                                4, ENC_BIG_ENDIAN);
            offset += 4;
        }

        if (raknet_tree) {
            bool is_ACK = true;
            return raknet_dissect_ACK(tvb_new_subset_remaining(tvb, offset),
                                      pinfo, raknet_tree, &is_ACK);
        }
        else {
            return tvb_captured_length(tvb);
        }
    }
    else if (msg_type & (1 << 5)) { /* isNAK */
        static int * const nak_flds[] = {
            &hf_raknet_packet_is_for_connected,
            &hf_raknet_packet_is_ACK,
            &hf_raknet_packet_is_NAK,
            NULL
        };

        ti = proto_tree_add_item(root_tree, proto_raknet, tvb, 0, -1, ENC_NA);
        proto_item_append_text(ti, ", NAK");
        raknet_tree = proto_item_add_subtree(ti, ett_raknet);

        proto_tree_add_bitmask(raknet_tree, tvb, offset, hf_raknet_packet_type,
                               ett_raknet_packet_type, nak_flds, ENC_NA);
        offset += 1;

        if (raknet_tree) {
            bool is_ACK = false;
            return raknet_dissect_ACK(tvb_new_subset_remaining(tvb, offset),
                                      pinfo, raknet_tree, &is_ACK);
        }
        else {
            return tvb_captured_length(tvb);
        }
    }
    else {
        /*
         * This is the trickiest part as it's neither ACK nor NAK. The
         * length of its RakNet header varies, and its payload can
         * even be fragmented so we might have to reassemble them.
         */
        uint32_t packet_number;
        bool has_multiple_messages = false;
        static int * const common_flds[] = {
            &hf_raknet_packet_is_for_connected,
            &hf_raknet_packet_is_ACK,
            &hf_raknet_packet_is_NAK,
            &hf_raknet_packet_is_pair,
            &hf_raknet_packet_is_continuous_send,
            &hf_raknet_packet_needs_B_and_AS,
            NULL
        };

        ti = proto_tree_add_item(root_tree, proto_raknet, tvb, 0, 0, ENC_NA);
        raknet_tree = proto_item_add_subtree(ti, ett_raknet);

        proto_tree_add_bitmask(raknet_tree, tvb, offset, hf_raknet_packet_type,
                               ett_raknet_packet_type, common_flds, ENC_NA);
        offset += 1;

        proto_tree_add_item_ret_uint(raknet_tree, hf_raknet_packet_number, tvb,
                                     offset, 3, ENC_LITTLE_ENDIAN, &packet_number);
        offset += 3;

        proto_item_append_text(ti, ", Message #%" PRIu32, packet_number);
        col_add_fstr(pinfo->cinfo, COL_INFO, "#%" PRIu32 ": ", packet_number);
        col_set_fence(pinfo->cinfo, COL_INFO);

        /*
         * Set the length of the top-level item to the size of packet
         * header as we don't know the correct size yet. The common
         * message dissector will later resize it.
         */
        proto_item_set_len(ti, offset);

        while (true) {
            int dissected;

            dissected = raknet_dissect_common_message(tvb_new_subset_remaining(tvb, offset), pinfo,
                                                      raknet_tree, &has_multiple_messages);
            if (dissected >= 0) {
                offset += dissected;

                if (tvb_reported_length_remaining(tvb, offset) > 0) {
                    /*
                     * More messages are in the packet.
                     */
                    col_append_fstr(pinfo->cinfo, COL_INFO, ", ");
                    col_set_fence(pinfo->cinfo, COL_INFO);
                    continue;
                }
                else {
                    /*
                     * It's the end of packet.
                     */
                    break;
                }
            }
            else {
                return dissected;
            }
        }

        return tvb_captured_length(tvb);
    }
}

/*
 * Decode the tvb buffer.
 *
 * RakNet is just a dissector.  It is invoked by protocols whose applications
 * are built using the RakNet libs.
 */
static int
dissect_raknet(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data)
{
    uint8_t message_id;
    int dissected;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "RakNet");
    col_clear(pinfo->cinfo, COL_INFO);

    message_id = tvb_get_uint8(tvb, 0);

    dissected = dissector_try_uint_new(raknet_offline_message_dissectors, message_id, tvb,
                                       pinfo, tree, true, data);
    if (!dissected) {
        raknet_dissect_connected_message(tvb, pinfo, tree, data);
    }

    return tvb_captured_length(tvb);
}

/*
 * Applications using RakNet do not always use a fixed port, but since
 * every RakNet sessions start with offline messages we can do
 * heuristics to detect such sessions.
 */
static bool
test_raknet_heur(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree _U_, void* data _U_)
{
    if (tvb_memeql(tvb, 1 + 8, RAKNET_OFFLINE_MESSAGE_DATA_ID, sizeof(RAKNET_OFFLINE_MESSAGE_DATA_ID)) == 0) {
        /* ID_UNCONNECTED_PING */
        return true;
    }
    else if (tvb_memeql(tvb, 1, RAKNET_OFFLINE_MESSAGE_DATA_ID, sizeof(RAKNET_OFFLINE_MESSAGE_DATA_ID)) == 0) {
        /* ID_OPEN_CONNECTION_REQUEST_1 */
        return true;
    }
    else if (tvb_memeql(tvb, 1 + 8 + 8, RAKNET_OFFLINE_MESSAGE_DATA_ID, sizeof(RAKNET_OFFLINE_MESSAGE_DATA_ID)) == 0) {
        /* ID_UNCONNECTED_PONG */
        return true;
    }
    else {
        return false;
    }
}

static bool
dissect_raknet_heur(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data)
{
    if (test_raknet_heur(tvb, pinfo, tree, data)) {
        conversation_t* conversation;

        conversation = find_or_create_conversation(pinfo);
        conversation_set_dissector(conversation, raknet_handle);

        return call_dissector_only(raknet_handle, tvb, pinfo, tree, data) > 0;
    }
    else {
        return false;
    }
}

void
proto_register_raknet(void)
{
    static hf_register_info hf[] = {
        /*
         * Offline Message ID field.
         */
        { &hf_raknet_offline_message_id,
            { "RakNet Offline Message ID", "raknet.offline.message.id",
                FT_UINT8, BASE_HEX,
                VALS(raknet_offline_message_names), 0x0,
                NULL, HFILL }
        },
        /*
         * General fields (fields in >1 packet).
         */
        { &hf_raknet_client_guid,
            { "RakNet Client GUID", "raknet.client.guid",
                FT_BYTES, BASE_NONE,
                NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_raknet_timestamp,
            { "RakNet Time since start (ms)", "raknet.timestamp",
                FT_UINT64, BASE_DEC,
                NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_raknet_offline_message_data_id,
            { "RakNet Offline message data ID", "raknet.offline_message.data_id",
                FT_BYTES, BASE_NONE,
                NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_raknet_mtu_size,
            { "RakNet MTU size", "raknet.MTU",
                FT_UINT16, BASE_DEC,
                NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_raknet_raknet_proto_ver,
            { "RakNet RakNet protocol version", "raknet.proto_ver",
                FT_UINT8, BASE_DEC,
                NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_raknet_server_guid,
            { "RakNet Server GUID", "raknet.server_id",
                FT_BYTES, BASE_NONE,
                NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_raknet_ip_version,
            { "RakNet IP Version", "raknet.ip.version",
                FT_UINT8, BASE_DEC,
                NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_raknet_ipv4_address,
            { "RakNet IPv4 Address", "raknet.ip.v4_address",
                FT_IPv4, BASE_NONE,
                NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_raknet_ipv6_address,
            { "RakNet IPv6 Address", "raknet.ip.v6_address",
                FT_IPv6, BASE_NONE,
                NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_raknet_port,
            { "RakNet Port", "raknet.port",
                FT_UINT16, BASE_DEC,
                NULL, 0x0,
                NULL, HFILL }
        },
        /*
         * Packet ID 0x05
         */
        { &hf_raknet_null_padding,
            { "RakNet Null padding", "raknet.null_padding",
                FT_NONE, BASE_NONE,
                NULL, 0x0,
                NULL, HFILL }
        },
        /*
         * Packet ID 0x06
         */
        { &hf_raknet_use_encryption,
            { "RakNet Use encryption", "raknet.use_encryption",
                FT_BOOLEAN, BASE_NONE,
                NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_raknet_server_public_key,
            { "RakNet Server public key", "raknet.server.public_key",
                FT_BYTES, BASE_NONE,
                NULL, 0x0,
                NULL, HFILL }
        },
        /*
         * Packet ID 0x07
         */
        { &hf_raknet_cookie,
            { "RakNet cookie", "raknet.cookie",
                FT_UINT32, BASE_HEX,
                NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_raknet_client_wrote_challenge,
            { "RakNet Client wrote challenge", "raknet.client.wrote_challenge",
                FT_BOOLEAN, BASE_NONE,
                NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_raknet_client_challenge,
            { "RakNet Client challenge", "raknet.client.challenge",
                FT_BYTES, BASE_NONE,
                NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_raknet_client_address,
            { "RakNet Client address", "raknet.client.address",
                FT_STRING, BASE_NONE,
                NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_raknet_server_address,
            { "RakNet Server address", "raknet.server.address",
                FT_STRING, BASE_NONE,
                NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_raknet_server_answer,
            { "RakNet Server answer", "raknet.server.answer",
                FT_BYTES, BASE_NONE,
                NULL, 0x0,
                NULL, HFILL }
        },
        /*
         * Packet ID 0x1C
         */
        { &hf_raknet_0x1C_server_id_str_len,
            { "RakNet Server ID string len", "raknet.server_id_str_len",
                FT_UINT16, BASE_DEC,
                NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_raknet_0x1C_server_id_str,
            { "RakNet Server ID string", "raknet.server_id_str",
                FT_STRING, BASE_NONE,
                NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_raknet_packet_type,
            { "RakNet Packet type", "raknet.packet.type",
                FT_UINT8, BASE_HEX,
                NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_raknet_packet_is_for_connected,
            { "is for connected peer", "raknet.packet.is_for_connected",
                FT_BOOLEAN, 8,
                NULL, 0x80,
                NULL, HFILL }
        },
        { &hf_raknet_packet_is_ACK,
            { "is ACK", "raknet.packet.is_ACK",
                FT_BOOLEAN, 8,
                NULL, 0x40,
                NULL, HFILL }
        },
        { &hf_raknet_packet_has_B_and_AS,
            { "has B and AS", "raknet.packet.has_B_and_AS",
                FT_BOOLEAN, 8,
                NULL, 0x20,
                NULL, HFILL }
        },
        { &hf_raknet_packet_is_NAK,
            { "is NAK", "raknet.packet.is_NAK",
                FT_BOOLEAN, 8,
                NULL, 0x20,
                NULL, HFILL }
        },
        { &hf_raknet_packet_is_pair,
            { "is pair", "raknet.packet.is_pair",
                FT_BOOLEAN, 8,
                NULL, 0x10,
                NULL, HFILL }
        },
        { &hf_raknet_packet_is_continuous_send,
            { "is continuous send", "raknet.packet.is_continuous_send",
                FT_BOOLEAN, 8,
                NULL, 0x8,
                NULL, HFILL }
        },
        { &hf_raknet_packet_needs_B_and_AS,
            { "needs B and AS", "raknet.packet.needs_B_and_AS",
                FT_BOOLEAN, 8,
                NULL, 0x4,
                NULL, HFILL }
        },
        { &hf_raknet_AS,
            { "RakNet Data arrival rate", "raknet.AS",
                FT_FLOAT, BASE_NONE,
                NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_raknet_NACK_record_count,
            { "RakNet ACK/NAK record count", "raknet.NACK.record_count",
                FT_UINT16, BASE_DEC,
                NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_raknet_packet_number_range,
            { "RakNet Packet sequence number range", "raknet.range.packet_number",
                FT_STRING, BASE_NONE,
                NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_raknet_range_max_equal_to_min,
            { "RakNet Range max equals to min", "raknet.range.max_equals_to_min",
                FT_BOOLEAN, BASE_NONE,
                NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_raknet_packet_number_min,
            { "RakNet Packet sequence number min", "raknet.range.packet_number.min",
                FT_UINT24, BASE_DEC,
                NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_raknet_packet_number_max,
            { "RakNet Packet sequence number max", "raknet.range.packet_number.max",
                FT_UINT24, BASE_DEC,
                NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_raknet_packet_number,
            { "RakNet Packet sequence number", "raknet.packet_number",
                FT_UINT24, BASE_DEC,
                NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_raknet_message,
            { "RakNet Message", "raknet.message",
                FT_NONE, BASE_NONE,
                NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_raknet_message_flags,
            { "RakNet Message flags", "raknet.message.flags",
                FT_UINT8, BASE_HEX,
                NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_raknet_message_reliability,
            { "reliability", "raknet.message.reliability",
                FT_UINT8, BASE_DEC,
                VALS(raknet_reliability), 0xE0,
                NULL, HFILL }
        },
        { &hf_raknet_message_has_split_packet,
            { "has split packet", "raknet.message.has_split_packet",
                FT_BOOLEAN, 8,
                NULL, 0x10,
                NULL, HFILL }
        },
        { &hf_raknet_payload_length,
            { "RakNet Payload length", "raknet.payload.length",
                FT_UINT16, BASE_DEC,
                NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_raknet_reliable_message_number,
            { "RakNet Reliable message number", "raknet.reliable.number",
                FT_UINT24, BASE_DEC,
                NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_raknet_message_sequencing_index,
            { "RakNet Message sequencing index", "raknet.sequencing.index",
                FT_UINT24, BASE_DEC,
                NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_raknet_message_ordering_index,
            { "RakNet Message ordering index", "raknet.ordering.index",
                FT_UINT24, BASE_DEC,
                NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_raknet_message_ordering_channel,
            { "RakNet Message ordering channel", "raknet.ordering.channel",
                FT_UINT8, BASE_DEC,
                NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_raknet_split_packet_count,
            { "RakNet Split packet count", "raknet.split.count",
                FT_UINT32, BASE_DEC,
                NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_raknet_split_packet_id,
            { "RakNet Split packet ID", "raknet.split.id",
                FT_UINT16, BASE_DEC,
                NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_raknet_split_packet_index,
            { "RakNet Split packet index", "raknet.split.index",
                FT_UINT32, BASE_DEC,
                NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_raknet_split_packet,
            { "RakNet Split packet", "raknet.split.packet",
                FT_NONE, BASE_NONE,
                NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_raknet_system_message,
            { "RakNet System message", "raknet.system.message",
                FT_NONE, BASE_NONE,
                NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_raknet_system_message_id,
            { "RakNet System Message ID", "raknet.system.message.id",
                FT_UINT8, BASE_HEX,
                VALS(raknet_system_message_names), 0x0,
                NULL, HFILL }
        },
        { &hf_raknet_client_proof,
            { "RakNet Client proof of key", "raknet.client.proof",
                FT_BYTES, BASE_NONE,
                NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_raknet_use_client_key,
            { "RakNet Use client key", "raknet.use_client_key",
                FT_BOOLEAN, BASE_NONE,
                NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_raknet_client_identity,
            { "RakNet Client identity", "raknet.client.identity",
                FT_BYTES, BASE_NONE,
                NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_raknet_password,
            { "RakNet Password", "raknet.password",
                FT_BYTES, BASE_NONE,
                NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_raknet_system_index,
            { "RakNet System index", "raknet.system.index",
                FT_UINT16, BASE_DEC,
                NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_raknet_internal_address,
            { "RakNet Internal address", "raknet.internal.address",
                FT_STRING, BASE_NONE,
                NULL, 0x0,
                NULL, HFILL }
        },
        /*
         * Fragmented packets
         */
        { &hf_raknet_fragment,
            { "Message fragment", "raknet.fragment",
                FT_FRAMENUM, BASE_NONE,
                NULL, 0x00,
                NULL, HFILL }
        },
        { &hf_raknet_fragment_count,
            { "Message fragment count", "raknet.fragment.count",
                FT_UINT32, BASE_DEC,
                NULL, 0x00,
                NULL, HFILL }
        },
        { &hf_raknet_fragment_error,
            { "Message defragmentation error", "raknet.fragment.error",
                FT_FRAMENUM, BASE_NONE,
                NULL, 0x00,
                NULL, HFILL }
        },
        { &hf_raknet_fragment_multiple_tails,
            { "Message has multiple tail fragments", "raknet.fragment.multiple_tails",
                FT_BOOLEAN, BASE_NONE,
                NULL, 0x00,
                NULL, HFILL }
        },
        { &hf_raknet_fragment_overlap,
            { "Message fragment overlap", "raknet.fragment.overlap",
                FT_BOOLEAN, BASE_NONE,
                NULL, 0x00,
                NULL, HFILL }
        },
        { &hf_raknet_fragment_overlap_conflicts,
            { "Message fragment overlapping with conflicting data", "raknet.fragment.overlap.conflicts",
                FT_BOOLEAN, BASE_NONE,
                NULL, 0x00,
                NULL, HFILL }
        },
        { &hf_raknet_fragment_too_long_fragment,
            { "Message fragment too long", "raknet.fragment.too_long",
                FT_BOOLEAN, BASE_NONE,
                NULL, 0x00,
                NULL, HFILL }
        },
        { &hf_raknet_fragments,
            { "Message fragments", "raknet.fragments",
                FT_NONE, BASE_NONE,
                NULL, 0x00,
                NULL, HFILL }
        },
        { &hf_raknet_reassembled_in,
            { "Reassembled message in frame", "raknet.reassembled.in",
                FT_FRAMENUM, BASE_NONE,
                NULL, 0x00,
                NULL, HFILL }
        },
        { &hf_raknet_reassembled_length,
            { "Reassembled message length", "raknet.reassembled.length",
                FT_UINT32, BASE_DEC,
                NULL, 0x00,
                NULL, HFILL }
        },
    };

    /*
     * Setup protocol subtree array
     */
    static int *ett[] = {
        &ett_raknet,
        &ett_raknet_system_address,
        &ett_raknet_packet_type,
        &ett_raknet_packet_number_range,
        &ett_raknet_message,
        &ett_raknet_message_flags,
        &ett_raknet_system_message,
        &ett_raknet_fragment,
        &ett_raknet_fragments,
    };

    /*
     * Set up expert info.
     */
    static ei_register_info ei[] = {
        { &ei_raknet_unknown_message_id,
          { "raknet.unknown.id", PI_UNDECODED, PI_WARN,
            "RakNet unknown message ID",
            EXPFILL }
        },
        { &ei_raknet_encrypted_message,
          { "raknet.encrypted", PI_DECRYPTION, PI_NOTE,
            "RakNet encrypted message",
            EXPFILL }
        },
        { &ei_raknet_subdissector_failed,
          { "raknet.subdissector.failed", PI_MALFORMED, PI_NOTE,
            "RakNet message subdissector failed, trying the next candidate or heuristics",
            EXPFILL }
        },
        { &ei_raknet_ip_ver_invalid,
          { "raknet.ip_version.invalid", PI_PROTOCOL, PI_WARN,
            "Invalid IP version",
            EXPFILL }
        }
    };
    expert_module_t *expert_raknet;

    /*
     * Init data structs.
     */
    raknet_init_message_names();

    /*
     * Register the protocol with Wireshark.
     */
    proto_raknet = proto_register_protocol (
            "RakNet game networking protocol", /* name */
            "RakNet", /* short name */
            "raknet"  /* abbrev */
            );

    /*
     * Register expert support.
     */
    expert_raknet = expert_register_protocol(proto_raknet);
    expert_register_field_array(expert_raknet, ei, array_length(ei));

    /*
     * Register detailed dissection arrays.
     */
    proto_register_field_array(proto_raknet, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    /*
     * Register reassembly table.
     */
    reassembly_table_register(&raknet_reassembly_table,
                          &addresses_ports_reassembly_table_functions);

    /*
     * For internal use only
     */
    raknet_handle =
        register_dissector("raknet", dissect_raknet, proto_raknet);

    raknet_offline_message_dissectors =
        register_dissector_table("raknet.offline.message.id", "RakNet offline messages",
                                 proto_raknet, FT_UINT8, BASE_HEX);

    raknet_system_message_dissectors =
        register_dissector_table("raknet.system.message.id", "RakNet system messages",
                                 proto_raknet, FT_UINT8, BASE_HEX);

    /*
     * External protocols may register their port to this table via
     * "raknet_add_udp_dissector()".
     */
    raknet_port_dissectors =
        register_dissector_table("raknet.port", "Port for protocols on top of RakNet",
                                 proto_raknet, FT_UINT16, BASE_DEC);

    /*
     * ...and their heuristic dissector to this table.
     */
    raknet_heur_subdissectors =
        register_heur_dissector_list_with_description("raknet", "RakNet fallback", proto_raknet);
}

void
proto_reg_handoff_raknet(void)
{
    dissector_handle_t raknet_handle_tmp;
    unsigned int i;

    for (i = 0; i < array_length(raknet_offline_message_handlers); i++) {
        raknet_handle_tmp =
            create_dissector_handle(raknet_offline_message_handlers[i].dissector_fp,
                                    proto_raknet);
        dissector_add_uint("raknet.offline.message.id", raknet_offline_message_handlers[i].vs.value,
                           raknet_handle_tmp);
    }

    for (i = 0; i < array_length(raknet_system_message_handlers); i++) {
        raknet_handle_tmp =
            create_dissector_handle(raknet_system_message_handlers[i].dissector_fp,
                                    proto_raknet);
        dissector_add_uint("raknet.system.message.id", raknet_system_message_handlers[i].vs.value,
                           raknet_handle_tmp);
    }

    heur_dissector_add("udp", dissect_raknet_heur,
                       "RakNet over UDP", "raknet_udp", proto_raknet, HEURISTIC_ENABLE);
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
