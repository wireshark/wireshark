/* packet-ms-do.c
 * Routines for MS-DO (Microsoft Delivery Optimization) dissection
 * Copyright 2023, Benjamin Levine (binyamin.l@sygnia.co, levbinyamin@gmail.com)
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

 /*
 * Microsoft Delivery Optimization is an internal Windows protocol for exchanging updates between Windows peers.
 *
 * As of today there are no Microsoft official docs specifying the protocol itself,
 * this dissector was written as part of my research into MS-DO.
 * For a detailed explanation see our blog posts:
 * <Sygnia blog post>
 */

#include "config.h"

#include <epan/packet.h>
#include <epan/conversation.h>
#include <epan/expert.h>

void proto_reg_handoff_do(void);
void proto_register_do(void);

static int proto_do;
// Message types
static int hf_do_handshake_message;
static int hf_do_keepalive_message;
static int hf_do_choke_message;
static int hf_do_unchoke_message;
static int hf_do_interested_message;
static int hf_do_notinterested_message;
static int hf_do_have_message;
static int hf_do_bitfield_message;
static int hf_do_request_message;
static int hf_do_piece_message;
static int hf_do_cancel_message;
static int hf_do_heap_spraying_message;
static int hf_do_unknown_message;
// Handshake
static int hf_do_protocol_name;
static int hf_do_size;
static int hf_do_swarm_hash;
static int hf_do_peer_id;
static int hf_do_peer_id_suffix;
// Message header
static int hf_do_message_size;
static int hf_do_message_id;
// BitField
static int hf_do_bitfield;
static int hf_do_bitfield_piece;
static int hf_do_has_piece;
// Request & Piece
static int hf_do_piece_index;
static int hf_do_piece_start_offset;
static int hf_do_piece_size;
static int hf_do_piece_buffer;
static int hf_do_piece_response_size;
// "HeapSpraying"
static int hf_do_heap_spraying;

static int ett_do;
static int ett_do_handshake;
static int ett_do_message;
static int ett_do_bitfield;
static int ett_do_bitfield_single;

static expert_field ei_do_invalid_message_id;
static expert_field ei_do_invalid_message_length;

static dissector_handle_t do_handle;

#define DO_PORT (7680)

#define DO_CHOKE_ID (0)
#define DO_UNCHOKE_ID (1)
#define DO_INTERESTED_ID (2)
#define DO_NOTINTERESTED_ID (3)
#define DO_HAVE_ID (4)
#define DO_BITFIELD_ID (5)
#define DO_REQUEST_ID (6)
#define DO_PIECE_ID (7)
#define DO_CANCEL_ID (8)
#define DO_HEAPSPRAYING_ID (20)

static const value_string message_types[] = {
    { DO_CHOKE_ID, "Choke Message" },
    { DO_UNCHOKE_ID, "Unchoke Message" },
    { DO_INTERESTED_ID, "Interested Message" },
    { DO_NOTINTERESTED_ID, "NotInterested Message" },
    { DO_HAVE_ID, "Have Message" },
    { DO_BITFIELD_ID, "BitField Message" },
    { DO_REQUEST_ID, "Request Message" },
    { DO_PIECE_ID, "Piece Message" },
    { DO_CANCEL_ID, "Cancel Message" },
    { DO_HEAPSPRAYING_ID, "HeapSpraying Message" },
    { 0, NULL }
};

static value_string_ext message_types_ext = VALUE_STRING_EXT_INIT(message_types);

typedef bool (*do_dissect_callback_t)(tvbuff_t*, packet_info*, proto_tree*, uint32_t, uint8_t, unsigned*);

static const char*
do_get_direction_str(packet_info* pinfo)
{
    if (pinfo->match_uint == pinfo->destport)
    {
        return "Request";
    }
    else if (pinfo->match_uint == pinfo->srcport)
    {
        return "Reply";
    }
    // This shouldn't happen.
    else
    {
        DISSECTOR_ASSERT_NOT_REACHED();
    }
}

/**
* Function attempts to identify a handshake and if so, parses it.
* If not returns false.
*/
static bool
dissect_do_handshake(tvbuff_t* tvb, packet_info* pinfo, proto_tree* do_tree, unsigned* offset_ptr)
{
    uint8_t protocol_name_length = 0;
    uint32_t calculated_length = 0;
    proto_item* handshame_item = NULL;
    proto_tree* handshake_tree = NULL;

    /* Identify handshake heuristically.
    It's hard to detect a handshake as it has a different format to messages.
    We could search for the "\x0eSwarm protocol" string at the beginning,
    but the Microsoft code supports other options that may be relevant.
    Perhaps in the future use conversations, they would have to handle
    cases where the sniff begins in the middle without any handhsakes.
    As anyway that approach requires heuristically verifying for handshakes in the middle
    let's just do that every time without preserving a complex context. */
    protocol_name_length = tvb_get_uint8(tvb, *offset_ptr);
    calculated_length = 1 + protocol_name_length + 8 + 32 + 16 + 4;
    if (calculated_length != tvb_reported_length(tvb))
    {
        return false;
    }

    col_add_fstr(pinfo->cinfo, COL_INFO, "Handshake Message (%s)", do_get_direction_str(pinfo));

    handshame_item = proto_tree_add_item(do_tree, hf_do_handshake_message, tvb, 0, -1, ENC_NA);
    handshake_tree = proto_item_add_subtree(handshame_item, ett_do_handshake);

    proto_tree_add_item(handshake_tree, hf_do_protocol_name, tvb, *offset_ptr, 1, ENC_ASCII | ENC_BIG_ENDIAN);
    *offset_ptr += sizeof(protocol_name_length) + protocol_name_length;

    proto_tree_add_item(handshake_tree, hf_do_size, tvb, *offset_ptr, 8, ENC_BIG_ENDIAN);
    *offset_ptr += 8;

    proto_tree_add_item(handshake_tree, hf_do_swarm_hash, tvb, *offset_ptr, 32, ENC_NA);
    *offset_ptr += 32;

    proto_tree_add_item(handshake_tree, hf_do_peer_id, tvb, *offset_ptr, 16, ENC_BIG_ENDIAN);
    *offset_ptr += 16;

    proto_tree_add_item(handshake_tree, hf_do_peer_id_suffix, tvb, *offset_ptr, 4, ENC_BIG_ENDIAN);
    *offset_ptr += 4;

    return true;
}

static const char*
do_message_id_to_str(uint8_t message_id)
{
    return val_to_str_ext_const(message_id, &message_types_ext, "Unknown Message");
}

static int
do_message_id_to_hfindex(uint8_t message_id)
{
    switch (message_id)
    {
    case DO_CHOKE_ID:
        return hf_do_choke_message;
    case DO_UNCHOKE_ID:
        return hf_do_unchoke_message;
    case DO_INTERESTED_ID:
        return hf_do_interested_message;
    case DO_NOTINTERESTED_ID:
        return hf_do_notinterested_message;
    case DO_HAVE_ID:
        return hf_do_have_message;
    case DO_BITFIELD_ID:
        return hf_do_bitfield_message;
    case DO_REQUEST_ID:
        return hf_do_request_message;
    case DO_PIECE_ID:
        return hf_do_piece_message;
    case DO_CANCEL_ID:
        return hf_do_cancel_message;
    case DO_HEAPSPRAYING_ID:
        return hf_do_heap_spraying_message;
    default:
        return hf_do_unknown_message;
    }
}

/**
* Add a subtree for a single message and add the message header into it.
*/
static proto_tree*
do_add_message_tree(tvbuff_t* tvb, proto_tree* tree, uint8_t message_id, uint32_t message_full_size, unsigned* offset_ptr)
{
    proto_item* message_item = NULL;
    proto_tree* message_tree = NULL;

    message_item = proto_tree_add_item(tree, do_message_id_to_hfindex(message_id), tvb, *offset_ptr, message_full_size, ENC_NA);
    message_tree = proto_item_add_subtree(message_item, ett_do_message);

    proto_tree_add_item(message_tree, hf_do_message_size, tvb, *offset_ptr, 4, ENC_BIG_ENDIAN);
    *offset_ptr += 4;
    proto_tree_add_item(message_tree, hf_do_message_id, tvb, *offset_ptr, 1, ENC_NA);
    *offset_ptr += 1;

    return message_tree;
}

/**
* Add KeepAlive message into tree.
*/
static void
dissect_do_keepalive(tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree, unsigned* offset_ptr)
{
    proto_item* message_item = NULL;
    proto_tree* message_tree = NULL;

    col_append_sep_str(pinfo->cinfo, COL_INFO, NULL, "KeepAlive Message");

    message_item = proto_tree_add_item(tree, hf_do_keepalive_message, tvb, *offset_ptr, 4, ENC_NA);
    message_tree = proto_item_add_subtree(message_item, ett_do_message);
    proto_tree_add_item(message_tree, hf_do_message_size, tvb, *offset_ptr, 4, ENC_BIG_ENDIAN);
    *offset_ptr += 4;
}

/**
* Callback to add a message without variables, this is used for multiple simple messages.
*/
static bool
dissect_do_empty_message(tvbuff_t* tvb, packet_info* pinfo, proto_tree* message_tree, uint32_t message_size, uint8_t message_id, unsigned* offset_ptr)
{
    if (1 != message_size)
    {
        proto_tree_add_expert_format(message_tree, pinfo, &ei_do_invalid_message_length, tvb, *offset_ptr, message_size - 1,
            "Invalid message size: %u instead of %u", message_size, 1);
        *offset_ptr += message_size - 1;
        return false;
    }

    col_append_sep_str(pinfo->cinfo, COL_INFO, NULL, do_message_id_to_str(message_id));

    return true;
}

/**
* Callback to add a Have message.
*/
static bool
dissect_do_have(tvbuff_t* tvb, packet_info* pinfo, proto_tree* message_tree, uint32_t message_size, uint8_t message_id, unsigned* offset_ptr)
{
    uint32_t piece_index = -1;

    if (5 != message_size)
    {
        proto_tree_add_expert_format(message_tree, pinfo, &ei_do_invalid_message_length, tvb, *offset_ptr, message_size - 1,
            "Invalid message size: %u instead of %u", message_size, 5);
        *offset_ptr += message_size - 1;
        return false;
    }
    proto_tree_add_item_ret_uint(message_tree, hf_do_piece_index, tvb, *offset_ptr, 4, ENC_BIG_ENDIAN, &piece_index);
    *offset_ptr += 4;

    col_append_sep_fstr(pinfo->cinfo, COL_INFO, NULL, "%s (piece %u)", do_message_id_to_str(message_id), piece_index);

    return true;
}

/**
* Callback to add a BitField message.
*/
static bool
dissect_do_bitfield(tvbuff_t* tvb, packet_info* pinfo, proto_tree* message_tree, uint32_t message_size, _U_ uint8_t message_id, unsigned* offset_ptr)
{
    proto_item* bitfield_item = NULL;
    proto_tree* bitfield_tree = NULL;
    proto_item* piece_item = NULL;
    proto_tree* piece_tree = NULL;
    uint32_t total_has = 0;
    uint32_t bitfield_size = 0;
    uint32_t byte_index = 0;
    uint32_t bit_index = 0;
    uint8_t current_byte = 0;
    bool has_piece = false;
    uint32_t piece_index = 0;

    bitfield_size = message_size - 1;

    bitfield_item = proto_tree_add_item(message_tree, hf_do_bitfield, tvb, *offset_ptr, bitfield_size, ENC_NA);
    bitfield_tree = proto_item_add_subtree(bitfield_item, ett_do_bitfield);

    for (byte_index = 0; byte_index < bitfield_size; byte_index++)
    {
        current_byte = tvb_get_uint8(tvb, *offset_ptr);
        for (bit_index = 0; bit_index < 8; bit_index++)
        {
            has_piece = false;
            // Simplified from dosvc.dll!CBitField::_IsSet
            if (current_byte & (1 << (7 - bit_index)))
            {
                has_piece = true;
                total_has++;
            }
            piece_index = 8 * byte_index + bit_index;
            piece_item = proto_tree_add_string_format_value(bitfield_tree, hf_do_bitfield_piece, tvb, *offset_ptr, 1,
                NULL, "Index: %u, has: %s", piece_index, has_piece ? "true" : "false");
            piece_tree = proto_item_add_subtree(piece_item, ett_do_bitfield_single);
            proto_tree_add_uint(piece_tree, hf_do_piece_index, tvb, *offset_ptr, 1, piece_index);
            proto_tree_add_boolean(piece_tree, hf_do_has_piece, tvb, *offset_ptr, 1, has_piece);

        }
        *offset_ptr += 1;
    }

    col_append_sep_fstr(pinfo->cinfo, COL_INFO, NULL, "%s (has %u of %u pieces)",
        do_message_id_to_str(message_id), total_has, bitfield_size * 8);

    return true;
}

/**
* Callback to add a Request or Cancel message.
*/
static bool
dissect_do_request_cancel(tvbuff_t* tvb, _U_ packet_info* pinfo, proto_tree* message_tree, uint32_t message_size, uint8_t message_id, unsigned* offset_ptr)
{
    uint32_t piece_index = 0;
    uint32_t piece_start_offset = 0;
    uint32_t piece_size = 0;

    if (13 != message_size)
    {
        proto_tree_add_expert_format(message_tree, pinfo, &ei_do_invalid_message_length, tvb, *offset_ptr, message_size - 1,
            "Invalid message size: %u instead of %u", message_size, 13);
        *offset_ptr += message_size - 1;
        return false;
    }

    proto_tree_add_item_ret_uint(message_tree, hf_do_piece_index, tvb, *offset_ptr, 4, ENC_BIG_ENDIAN, &piece_index);
    *offset_ptr += 4;
    proto_tree_add_item_ret_uint(message_tree, hf_do_piece_start_offset, tvb, *offset_ptr, 4, ENC_BIG_ENDIAN, &piece_start_offset);
    *offset_ptr += 4;
    proto_tree_add_item_ret_uint(message_tree, hf_do_piece_size, tvb, *offset_ptr, 4, ENC_BIG_ENDIAN, &piece_size);
    *offset_ptr += 4;

    col_append_sep_fstr(pinfo->cinfo, COL_INFO, NULL, "%s (piece %u; offset 0x%x; size 0x%x)",
        do_message_id_to_str(message_id), piece_index, piece_start_offset, piece_size);

    return true;
}

/**
* Callback to add a Piece message.
*/
static bool
dissect_do_piece(tvbuff_t* tvb, _U_ packet_info* pinfo, proto_tree* message_tree, uint32_t message_size, uint8_t message_id, unsigned* offset_ptr)
{
    proto_item* pi = NULL;
    uint32_t piece_index = 0;
    uint32_t piece_start_offset = 0;
    uint32_t piece_size = 0;

    piece_size = message_size - 9;

    if (message_size <= 9)
    {
        proto_tree_add_expert_format(message_tree, pinfo, &ei_do_invalid_message_length, tvb, *offset_ptr, message_size - 1,
            "Invalid message size: message size %u must be larger than 9", message_size);
        *offset_ptr += message_size - 1;
        return false;
    }
    proto_tree_add_item_ret_uint(message_tree, hf_do_piece_index, tvb, *offset_ptr, 4, ENC_BIG_ENDIAN, &piece_index);
    *offset_ptr += 4;
    proto_tree_add_item_ret_uint(message_tree, hf_do_piece_start_offset, tvb, *offset_ptr, 4, ENC_BIG_ENDIAN, &piece_start_offset);
    *offset_ptr += 4;
    proto_tree_add_item(message_tree, hf_do_piece_buffer, tvb, *offset_ptr, message_size - 9, ENC_NA);
    *offset_ptr += message_size - 9;
    pi = proto_tree_add_uint(message_tree, hf_do_piece_response_size, NULL, 0, 0, piece_size);
    proto_item_set_generated(pi);

    col_append_sep_fstr(pinfo->cinfo, COL_INFO, NULL, "%s (piece %u; offset 0x%x; size 0x%x)",
        do_message_id_to_str(message_id), piece_index, piece_start_offset, piece_size);

    return true;
}

/**
* Callback to add a "HeapSpraying" message.
*/
static bool
dissect_do_heap_spraying(tvbuff_t* tvb, packet_info* pinfo, proto_tree* message_tree, uint32_t message_size, _U_ uint8_t message_id, unsigned* offset_ptr)
{
    proto_tree_add_item(message_tree, hf_do_heap_spraying, tvb, *offset_ptr, message_size - 1, ENC_NA);
    *offset_ptr += message_size - 1;

    col_append_sep_str(pinfo->cinfo, COL_INFO, NULL, do_message_id_to_str(message_id));

    return true;
}

/**
* Callback to handle an unknown message
* Just adds its size (which we have from the message header) to the offset.
*/
static bool
dissect_do_unkown_message(tvbuff_t* tvb, packet_info* pinfo, proto_tree* message_tree, uint32_t message_size, uint8_t message_id, unsigned* offset_ptr)
{
    proto_tree_add_expert_format(message_tree, pinfo, &ei_do_invalid_message_id, tvb, *offset_ptr, message_size - 1,
        "Unknown message ID: %u", message_id);

    *offset_ptr += message_size - 1;

    return true;
}

static do_dissect_callback_t
message_id_to_callback(uint8_t message_id)
{
    switch (message_id)
    {
    case DO_CHOKE_ID:
    case DO_UNCHOKE_ID:
    case DO_INTERESTED_ID:
    case DO_NOTINTERESTED_ID:
        return &dissect_do_empty_message;
    case DO_HAVE_ID:
        return &dissect_do_have;
    case DO_BITFIELD_ID:
        return &dissect_do_bitfield;
    case DO_REQUEST_ID:
    case DO_CANCEL_ID:
        return dissect_do_request_cancel;
    case DO_PIECE_ID:
        return &dissect_do_piece;
    case DO_HEAPSPRAYING_ID:
        return &dissect_do_heap_spraying;
    default:
        return &dissect_do_unkown_message;
    }
}

/**
* Parse a single message, on success return true.
* If true is returned but *desegment_len_ptr is non-zero, the message wasn't parsed as more bytes are required.
*/
static bool
dissect_do_message(tvbuff_t* tvb, packet_info* pinfo, proto_tree* do_tree, unsigned* offset_ptr, unsigned* desegment_len_ptr)
{
    unsigned buffer_size = 0;
    uint32_t message_size = 0;
    uint32_t message_full_size = 0;
    uint8_t message_id = -1;
    proto_tree* message_tree = NULL;

    buffer_size = tvb_reported_length_remaining(tvb, *offset_ptr);

    // Request more bytes if necessary
    if (buffer_size < 4)
    {
        *desegment_len_ptr = 4 - buffer_size;
        return true;
    }

    message_size = tvb_get_uint32(tvb, *offset_ptr, ENC_BIG_ENDIAN);

    // KeepAlive case
    if (0 == message_size)
    {
        dissect_do_keepalive(tvb, pinfo, do_tree, offset_ptr);
        return true;
    }

    if (buffer_size < message_size + 4)
    {
        // Message size (4 bytes) + required size - current size
        *desegment_len_ptr = 4 + message_size - buffer_size;
        return true;
    }

    message_id = tvb_get_uint8(tvb, *offset_ptr + 4);
    message_full_size = sizeof(message_size) + message_size;

    message_tree = do_add_message_tree(tvb, do_tree, message_id, message_full_size, offset_ptr);

    if (!(*message_id_to_callback(message_id))(tvb, pinfo, message_tree, message_size, message_id, offset_ptr))
    {
        return false;
    }

    return true;
}

static int
dissect_do(tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree, _U_ void* data)
{
    proto_item* ti = NULL;
    proto_tree* do_tree = NULL;

    // Using GLib types instead of standard interface to match existing API.
    unsigned offset = 0;
    uint32_t desegment_len = 0;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "MS-DO");
    col_clear(pinfo->cinfo, COL_INFO);

    if (0 == tvb_captured_length(tvb))
    {
        return tvb_captured_length(tvb);
    }

    ti = proto_tree_add_item(tree, proto_do, tvb, 0, -1, ENC_NA);
    do_tree = proto_item_add_subtree(ti, ett_do);

    // Multiple messages can be concatted, parse them one at a time.
    while (offset < tvb_reported_length(tvb))
    {
        // Check if this is a handshake message, if not parse it as a message
        if (dissect_do_handshake(tvb, pinfo, do_tree, &offset))
        {
            continue;
        }

        desegment_len = 0;
        if (dissect_do_message(tvb, pinfo, do_tree, &offset, &desegment_len))
        {
            if (desegment_len)
            {
                // Wait for more data.
                pinfo->desegment_offset = offset;
                pinfo->desegment_len = desegment_len;
                return tvb_reported_length(tvb);
            }
        }
        else
        {
            // Parsing error, stop parsing
            return tvb_captured_length(tvb);
        }
    }

    return offset;
};

void
proto_register_do(void)
{
    static hf_register_info hf[] = {
       { &hf_do_handshake_message,
            { "Handshake Message", "msdo.Handshake",
              FT_NONE, BASE_NONE, NULL, 0x0,
              NULL, HFILL }
       },
       { &hf_do_keepalive_message,
            { "KeepAlive Message", "msdo.KeepAlive",
              FT_NONE, BASE_NONE, NULL, 0x0,
              NULL, HFILL }
        },
       { &hf_do_choke_message,
            { "Choke Message", "msdo.Choke",
              FT_NONE, BASE_NONE, NULL, 0x0,
              NULL, HFILL }
        },
       { &hf_do_unchoke_message,
            { "UnChoke Message", "msdo.UnChoke",
              FT_NONE, BASE_NONE, NULL, 0x0,
              NULL, HFILL }
        },
       { &hf_do_interested_message,
            { "Interested Message", "msdo.Interested",
              FT_NONE, BASE_NONE, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_do_notinterested_message,
            { "NotInterested Message", "msdo.NotInterested",
              FT_NONE, BASE_NONE, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_do_have_message,
            { "Have Message", "msdo.Have",
              FT_NONE, BASE_NONE, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_do_bitfield_message,
            { "BitField Message", "msdo.BitField",
              FT_NONE, BASE_NONE, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_do_request_message,
            { "Request Message", "msdo.Request",
              FT_NONE, BASE_NONE, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_do_piece_message,
            { "Piece Message", "msdo.Piece",
              FT_NONE, BASE_NONE, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_do_cancel_message,
            { "Cancel Message", "msdo.Cancel",
              FT_NONE, BASE_NONE, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_do_heap_spraying_message,
            { "HeapSpraying Message", "msdo.HeapSpraying",
              FT_NONE, BASE_NONE, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_do_unknown_message,
            { "Unknown Message, this shouldn't happen", "msdo.UnknownMessage",
              FT_NONE, BASE_NONE, NULL, 0x0,
              NULL, HFILL }
        },

        { &hf_do_protocol_name,
            { "Protocol Name", "msdo.Handshake.ProtocolName",
              FT_UINT_STRING, BASE_NONE, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_do_size,
            { "Size", "msdo.Handshake.Size",
              FT_UINT64, BASE_HEX, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_do_swarm_hash,
            { "Swarm Hash", "msdo.Handshake.SwarmHash",
              FT_BYTES, BASE_NONE, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_do_peer_id,
            { "Peer Id", "msdo.Handshake.PeerId",
              FT_GUID, BASE_NONE, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_do_peer_id_suffix,
            { "Peer Id Suffix", "msdo.Handshake.PeerIdSuffix",
              FT_UINT32, BASE_HEX, NULL, 0x0,
              NULL, HFILL }
        },

        { &hf_do_message_size,
            { "Message Size", "msdo.MessageSize",
              FT_UINT32, BASE_HEX, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_do_message_id,
            { "Message Id", "msdo.MessageId",
              FT_UINT32, BASE_DEC | BASE_EXT_STRING, &message_types_ext, 0x0,
              NULL, HFILL }
        },

        { &hf_do_bitfield,
            { "Bit Field", "msdo.BitField.BitField",
              FT_BYTES, BASE_NONE, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_do_bitfield_piece,
            { "Bit Field", "msdo.BitField.Piece",
              FT_STRINGZ, BASE_NONE, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_do_has_piece,
            { "Has Piece", "msdo.BitField.HasPiece",
              FT_BOOLEAN, BASE_NONE, NULL, 0x0,
              NULL, HFILL }
        },

        { &hf_do_piece_index,
            { "Piece Index", "msdo.PieceIndex",
                FT_UINT32, BASE_DEC, NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_do_piece_start_offset,
            { "Piece Start Offset", "msdo.PieceStartOffset",
                FT_UINT32, BASE_HEX, NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_do_piece_size,
            { "Requested Piece Size", "msdo.PieceSize",
                FT_UINT32, BASE_HEX, NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_do_piece_buffer,
            { "Piece Buffer", "msdo.PieceBuffer",
                FT_BYTES, BASE_NONE, NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_do_piece_response_size,
            { "Response Piece Buffer Size", "msdo.PieceSize",
                FT_UINT32, BASE_HEX, NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_do_heap_spraying,
            { "Heap Spraying Buffer", "msdo.HeapSpraying.HeapSpraying",
                FT_BYTES, BASE_NONE, NULL, 0x0,
                NULL, HFILL }
        },
    };

    static int* ett[] = {
        &ett_do,
        &ett_do_handshake,
        &ett_do_message,
        &ett_do_bitfield,
        &ett_do_bitfield_single
    };

    static ei_register_info ei[] = {
        { &ei_do_invalid_message_id,     { "msdo.invalid_message_id", PI_MALFORMED, PI_WARN, "Unknown message ID", EXPFILL }},
        { &ei_do_invalid_message_length, { "msdo.invalid_message_length", PI_MALFORMED, PI_ERROR, "Invalid message size", EXPFILL}}
    };

    expert_module_t* expert_do = NULL;

    proto_do = proto_register_protocol("Microsoft Delivery Optimization", "MS-DO", "msdo");

    proto_register_field_array(proto_do, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
    expert_do = expert_register_protocol(proto_do);
    expert_register_field_array(expert_do, ei, array_length(ei));

    do_handle = register_dissector("msdo", dissect_do, proto_do);
}

void
proto_reg_handoff_do(void)
{
    static bool initialized = false;

    if (!initialized)
    {
        dissector_add_uint("tcp.port", DO_PORT, do_handle);

        initialized = true;
    }
}
