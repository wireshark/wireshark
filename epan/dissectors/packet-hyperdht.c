/* packet-hyperdht.c
 * Routines for DHT-RPC and HyperDHT dissection
 *
 * Copyright 2026, James Thomas <jthomas@holepunch.to>
 * Copyright 2026, Vijaygopal Balasa <balasavijaygopal@gmail.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/*
 * DHT-RPC is the UDP RPC layer that carries HyperDHT traffic, so a HyperDHT
 * dissector has to understand both the dht-rpc envelope and the per-command
 * payloads HyperDHT puts inside it.
 *
 * The dht-rpc envelope (dht-rpc/lib/io.js _encodeRequest/_sendReply) is:
 *
 *   byte 0    : type | version (0x03 request, 0x13 response)
 *   byte 1    : flags
 *   uint16 LE : transaction id
 *   6 bytes   : peer address (IPv4 + uint16 LE port)
 *   [32]      : node id        (flag 0x01)
 *   [32]      : token          (flag 0x02)
 *   (requests only)
 *   compact uint : command
 *   [32]      : target         (request flag 0x08)
 *   (responses only)
 *   compact array : closer nodes (response flag 0x04, 6-byte ipv4:port each)
 *   compact uint  : error        (response flag 0x08)
 *   (both)
 *   compact buffer : value       (flag 0x10)
 *
 * A response repeats neither the command nor the target, so a reply payload
 * can only be decoded once the request carrying the same transaction id has
 * been seen.
 *
 * HyperDHT command payloads are defined in hyperdht/lib/messages.js and the
 * command numbers in hyperdht/lib/constants.js. Encrypted payloads (the noise
 * handshake and the holepunch payload) are displayed as opaque bytes;
 * decryption and signature verification are out of scope.
 *
 * References:
 *   https://github.com/holepunchto/dht-rpc
 *   https://github.com/holepunchto/hyperdht
 */

#include "config.h"

#include <wireshark.h>

#include <epan/conversation.h>
#include <epan/expert.h>
#include <epan/packet.h>
#include <epan/proto_data.h>
#include <epan/to_str.h>
#include <epan/unit_strings.h>

void proto_register_hyperdht(void);
void proto_reg_handoff_hyperdht(void);

#define DHT_RPC_REQUEST_ID   0x03
#define DHT_RPC_RESPONSE_ID  0x13

/* Envelope layout */
#define DHT_TYPE_OFFSET      0
#define DHT_FLAGS_OFFSET     1
#define DHT_TID_OFFSET       2
#define DHT_ADDR_OFFSET      4
#define DHT_HEADER_LEN       10 /* type|version, flags, tid, address */
#define DHT_ADDR_LEN         6  /* IPv4 address + uint16 LE port */

#define DHT_TYPE_RESPONSE    0x10
#define DHT_TYPE_VERSION     0x0f

/* Fixed-width payload fields */
#define DHT_ID_LEN           32
#define DHT_TOKEN_LEN        32
#define DHT_TARGET_LEN       32
#define DHT_KEY_LEN          32
#define DHT_REFRESH_LEN      32
#define DHT_SIGNATURE_LEN    64

/* Envelope flags. 0x01, 0x02 and 0x10 mean the same thing in both directions;
 * 0x04 and 0x08 do not (dht-rpc/lib/io.js _encodeRequest vs _sendReply). */
#define DHT_FLAG_ID              0x01
#define DHT_FLAG_TOKEN           0x02
#define DHT_FLAG_VALUE           0x10
#define DHT_REQ_FLAG_INTERNAL    0x04
#define DHT_REQ_FLAG_TARGET      0x08
#define DHT_RESP_FLAG_CLOSER     0x04
#define DHT_RESP_FLAG_ERROR      0x08
#define DHT_FLAG_MASK            0x1f

/* Payload flags (hyperdht/lib/messages.js, each encoder's flags expression) */
#define HYPERDHT_HANDSHAKE_FLAG_PEER   0x01
#define HYPERDHT_HANDSHAKE_FLAG_RELAY  0x02
#define HYPERDHT_HOLEPUNCH_FLAG_PEER   0x01
#define HYPERDHT_ANNOUNCE_FLAG_PEER      0x01
#define HYPERDHT_ANNOUNCE_FLAG_REFRESH   0x02
#define HYPERDHT_ANNOUNCE_FLAG_SIGNATURE 0x04
#define HYPERDHT_ANNOUNCE_FLAG_BUMP      0x08
#define HYPERDHT_PLUGIN_FLAG_VALUE       0x01

/* dht-rpc internal commands (dht-rpc/lib/commands.js) */
enum {
    DHT_CMD_PING,
    DHT_CMD_PING_NAT,
    DHT_CMD_FIND_NODE,
    DHT_CMD_DOWN_HINT,
    DHT_CMD_DELAYED_PING
};

/* HyperDHT commands (hyperdht/lib/constants.js COMMANDS) */
enum {
    HYPERDHT_CMD_PEER_HANDSHAKE,
    HYPERDHT_CMD_PEER_HOLEPUNCH,
    HYPERDHT_CMD_FIND_PEER,
    HYPERDHT_CMD_LOOKUP,
    HYPERDHT_CMD_ANNOUNCE,
    HYPERDHT_CMD_UNANNOUNCE,
    HYPERDHT_CMD_MUTABLE_PUT,
    HYPERDHT_CMD_MUTABLE_GET,
    HYPERDHT_CMD_IMMUTABLE_PUT,
    HYPERDHT_CMD_IMMUTABLE_GET,
    HYPERDHT_CMD_PLUGIN
};

static const val64_string dhtrpc_command_names[] = {
    { DHT_CMD_PING,         "PING" },
    { DHT_CMD_PING_NAT,     "PING_NAT" },
    { DHT_CMD_FIND_NODE,    "FIND_NODE" },
    { DHT_CMD_DOWN_HINT,    "DOWN_HINT" },
    { DHT_CMD_DELAYED_PING, "DELAYED_PING" },
    { 0, NULL }
};

static const val64_string hyperdht_command_names[] = {
    { HYPERDHT_CMD_PEER_HANDSHAKE, "PEER_HANDSHAKE" },
    { HYPERDHT_CMD_PEER_HOLEPUNCH, "PEER_HOLEPUNCH" },
    { HYPERDHT_CMD_FIND_PEER,      "FIND_PEER" },
    { HYPERDHT_CMD_LOOKUP,         "LOOKUP" },
    { HYPERDHT_CMD_ANNOUNCE,       "ANNOUNCE" },
    { HYPERDHT_CMD_UNANNOUNCE,     "UNANNOUNCE" },
    { HYPERDHT_CMD_MUTABLE_PUT,    "MUTABLE_PUT" },
    { HYPERDHT_CMD_MUTABLE_GET,    "MUTABLE_GET" },
    { HYPERDHT_CMD_IMMUTABLE_PUT,  "IMMUTABLE_PUT" },
    { HYPERDHT_CMD_IMMUTABLE_GET,  "IMMUTABLE_GET" },
    { HYPERDHT_CMD_PLUGIN,         "PLUGIN" },
    { 0, NULL }
};

/* One error namespace covers both command layers: dht-rpc answers any request
 * with UNKNOWN_COMMAND or INVALID_TOKEN (dht-rpc/index.js _onrequest,
 * dht-rpc/lib/io.js), and the storage commands add SEQ_REUSED/SEQ_TOO_LOW
 * (hyperdht/lib/persistent.js). The remaining hyperdht error codes
 * (ABORTED/VERSION_MISMATCH/TRY_LATER, hyperdht/lib/constants.js ERROR)
 * travel inside the encrypted payloads and never reach the envelope. */
static const val64_string dht_error_names[] = {
    { 0,  "NONE" },   /* mirrors the enum; io.js sets the error flag only when error > 0 */
    { 1,  "UNKNOWN_COMMAND" },
    { 2,  "INVALID_TOKEN" },
    { 16, "SEQ_REUSED" },
    { 17, "SEQ_TOO_LOW" },
    { 0, NULL }
};

/* Handshake and holepunch share one mode namespace (hyperdht/lib/router.js) */
#define HYPERDHT_MODE_FROM_CLIENT       0
#define HYPERDHT_MODE_FROM_SERVER       1
#define HYPERDHT_MODE_FROM_RELAY        2
#define HYPERDHT_MODE_FROM_SECOND_RELAY 3
#define HYPERDHT_MODE_REPLY             4

static const value_string holepunch_mode_names[] = {
    { HYPERDHT_MODE_FROM_CLIENT,       "FROM_CLIENT" },
    { HYPERDHT_MODE_FROM_SERVER,       "FROM_SERVER" },
    { HYPERDHT_MODE_FROM_RELAY,        "FROM_RELAY" },
    { HYPERDHT_MODE_FROM_SECOND_RELAY, "FROM_SECOND_RELAY" },
    { HYPERDHT_MODE_REPLY,             "REPLY" },
    { 0, NULL }
};

/*
 * Compact encoding (the compact-encoding npm module). Only the types that
 * appear on this wire are decoded:
 *   - compact integers: 1 byte <= 0xfc, else 0xfd/u16le, 0xfe/u32le, 0xff/u64le
 *   - compact buffers: compact-integer length prefix + data
 *   - compact arrays of fixed-size elements: compact-integer count + elements
 */
typedef struct {
    int      offset; /* start of the encoded integer */
    int      size;   /* total encoded size in bytes */
    uint64_t value;
} compact_integer_t;

/* Lengths and counts are 64-bit on the wire but are clamped to the bytes the
 * enclosing container actually holds, so size/data_size/nelts are always
 * usable as int offsets and lengths. The value as encoded is kept for
 * display only. */
typedef struct {
    int      offset;      /* start of the length prefix */
    int      size;        /* total size: length prefix + clamped data */
    int      data_offset;
    int      data_size;
    uint64_t declared_size;
    bool     truncated;   /* declared_size ran past the end of the container */
} compact_buffer_t;

typedef struct {
    int      offset;      /* start of the count prefix */
    int      size;        /* total size: count prefix + clamped elements */
    int      nelts;
    int      data_offset;
    uint64_t declared_nelts;
    bool     truncated;
} compact_array_t;

/* Encoded width of the compact integer starting with b0. Shared so the
 * heuristic bounds check and the decoder cannot disagree about it. */
static int
compact_integer_size(uint8_t b0)
{
    if (b0 <= 0xfc)
        return 1;
    if (b0 == 0xfd)
        return 3;
    if (b0 == 0xfe)
        return 5;
    return 9;
}

static int
decode_compact_integer(tvbuff_t *tvb, int offset, compact_integer_t *p)
{
    uint8_t b0;

    p->offset = offset;
    b0 = tvb_get_uint8(tvb, offset);
    p->size = compact_integer_size(b0);

    switch (p->size) {
    case 3:
        p->value = tvb_get_uint16(tvb, offset + 1, ENC_LITTLE_ENDIAN);
        break;
    case 5:
        p->value = tvb_get_uint32(tvb, offset + 1, ENC_LITTLE_ENDIAN);
        break;
    case 9:
        p->value = tvb_get_uint64(tvb, offset + 1, ENC_LITTLE_ENDIAN);
        break;
    default:
        p->value = b0;
        break;
    }

    return p->size;
}

/* Bounds check for the heuristic path, which must not throw before returning
 * false (README.heuristic): 0xfd/0xfe/0xff read 2, 4 or 8 bytes past b0.
 * Unlike compact_integer_fits() this asks whether the bytes were captured,
 * because a heuristic verdict may not depend on data that is not there. */
static bool
compact_integer_present(tvbuff_t *tvb, int offset)
{
    if (!tvb_bytes_exist(tvb, offset, 1))
        return false;

    return tvb_bytes_exist(tvb, offset, compact_integer_size(tvb_get_uint8(tvb, offset)));
}

/* Whether a compact integer at offset stays inside the container ending at
 * end. A wider prefix than the container has room for means the payload is
 * short, not that more bytes follow. */
static bool
compact_integer_fits(tvbuff_t *tvb, int offset, int end)
{
    if (offset >= end)
        return false;

    return end - offset >= compact_integer_size(tvb_get_uint8(tvb, offset));
}

static int
decode_compact_buffer(tvbuff_t *tvb, int offset, int end, compact_buffer_t *p)
{
    compact_integer_t len_prefix;
    uint64_t          avail;

    p->offset = offset;
    decode_compact_integer(tvb, offset, &len_prefix);

    p->data_offset = offset + len_prefix.size;
    p->declared_size = len_prefix.value;

    /* Clamp before the length reaches int arithmetic: truncating a 64-bit
     * length makes a huge buffer parse as a small one. */
    avail = (p->data_offset < end) ? (uint64_t)(end - p->data_offset) : 0;
    p->truncated = len_prefix.value > avail;
    p->data_size = p->truncated ? (int)avail : (int)len_prefix.value;
    p->size = len_prefix.size + p->data_size;

    return p->size;
}

static int
decode_compact_array(tvbuff_t *tvb, int offset, int end, int element_size,
                     compact_array_t *p)
{
    compact_integer_t nelts;
    uint64_t          avail;

    p->offset = offset;
    decode_compact_integer(tvb, offset, &nelts);

    p->data_offset = offset + nelts.size;
    p->declared_nelts = nelts.value;

    /* Divide the bytes that are left rather than multiplying the count:
     * count * element_size is a 64-bit product that would wrap. */
    avail = (p->data_offset < end) ? (uint64_t)(end - p->data_offset) : 0;
    p->truncated = nelts.value > avail / (uint64_t)element_size;
    p->nelts = p->truncated ? (int)(avail / (uint64_t)element_size)
                            : (int)nelts.value;
    p->size = nelts.size + p->nelts * element_size;

    return p->size;
}

/* One past the last byte the value declared. Command payloads are bounded by
 * the value that carried them, not by the packet: dht-rpc hands the command
 * handler exactly these bytes (dht-rpc/lib/io.js), and a value too short for
 * the encoding its command implies is discarded by the peer, so it has to
 * render as a partial decode here rather than as a malformed packet. */
static int
dht_value_end(const compact_buffer_t *value)
{
    return value->data_offset + value->data_size;
}

static int
dht_value_bytes_left(const compact_buffer_t *value, int offset)
{
    return dht_value_end(value) - offset;
}

static int proto_hyperdht;

/* envelope */
static int hf_hyperdht_response;
static int hf_hyperdht_version;
static int hf_hyperdht_flags;
static int hf_hyperdht_flag_id;
static int hf_hyperdht_flag_token;
static int hf_hyperdht_flag_internal;
static int hf_hyperdht_flag_closer_nodes;
static int hf_hyperdht_flag_target;
static int hf_hyperdht_flag_error;
static int hf_hyperdht_flag_value;
static int hf_hyperdht_tid;
static int hf_hyperdht_peer;
static int hf_hyperdht_peer_ipv4;
static int hf_hyperdht_peer_port;
static int hf_hyperdht_id;
static int hf_hyperdht_token;
static int hf_hyperdht_command;
static int hf_hyperdht_dhtrpc_command;
static int hf_hyperdht_target;
static int hf_hyperdht_value;
static int hf_hyperdht_error;
static int hf_hyperdht_closer_nodes;
static int hf_hyperdht_closer_node;
static int hf_hyperdht_closer_node_ipv4;
static int hf_hyperdht_closer_node_port;

/* dht-rpc command payloads */
static int hf_hyperdht_ping_nat_port;
static int hf_hyperdht_down_hint_node;
static int hf_hyperdht_down_hint_node_ipv4;
static int hf_hyperdht_down_hint_node_port;
static int hf_hyperdht_delayed_ping_ms;

/* peer_handshake / peer_holepunch */
static int hf_hyperdht_handshake_flags;
static int hf_hyperdht_handshake_flag_peer;
static int hf_hyperdht_handshake_flag_relay;
static int hf_hyperdht_handshake_mode;
static int hf_hyperdht_handshake_noise;
static int hf_hyperdht_handshake_peer;
static int hf_hyperdht_handshake_peer_ipv4;
static int hf_hyperdht_handshake_peer_port;
static int hf_hyperdht_handshake_relay;
static int hf_hyperdht_handshake_relay_ipv4;
static int hf_hyperdht_handshake_relay_port;
static int hf_hyperdht_holepunch_flags;
static int hf_hyperdht_holepunch_flag_peer;
static int hf_hyperdht_holepunch_mode;
static int hf_hyperdht_holepunch_id;
static int hf_hyperdht_holepunch_payload;
static int hf_hyperdht_holepunch_peer;
static int hf_hyperdht_holepunch_peer_ipv4;
static int hf_hyperdht_holepunch_peer_port;

/* announce / unannounce */
static int hf_hyperdht_announce_flags;
static int hf_hyperdht_announce_flag_peer;
static int hf_hyperdht_announce_flag_refresh;
static int hf_hyperdht_announce_flag_signature;
static int hf_hyperdht_announce_flag_bump;
static int hf_hyperdht_announce_peer;
static int hf_hyperdht_announce_peer_relay;
static int hf_hyperdht_announce_peer_relay_ipv4;
static int hf_hyperdht_announce_peer_relay_port;
static int hf_hyperdht_announce_refresh;
static int hf_hyperdht_announce_signature;
static int hf_hyperdht_announce_bump;

/* mutable / immutable */
static int hf_hyperdht_mutable_put_public_key;
static int hf_hyperdht_mutable_put_seq;
static int hf_hyperdht_mutable_put_value;
static int hf_hyperdht_mutable_put_signature;
static int hf_hyperdht_mutable_get_req_seq;
static int hf_hyperdht_mutable_get_resp_seq;
static int hf_hyperdht_mutable_get_resp_value;
static int hf_hyperdht_mutable_get_resp_signature;
static int hf_hyperdht_immutable_value;

/* plugin */
static int hf_hyperdht_plugin_name;
static int hf_hyperdht_plugin_version;
static int hf_hyperdht_plugin_command;
static int hf_hyperdht_plugin_flags;
static int hf_hyperdht_plugin_flag_value;
static int hf_hyperdht_plugin_value;
static int hf_hyperdht_plugin_resp_value;

/* lookup / find_peer responses */
static int hf_hyperdht_lookup_peer_count;
static int hf_hyperdht_lookup_peer;
static int hf_hyperdht_lookup_peer_relay;
static int hf_hyperdht_lookup_peer_relay_ipv4;
static int hf_hyperdht_lookup_peer_relay_port;
static int hf_hyperdht_lookup_bump;
static int hf_hyperdht_find_peer_peer;
static int hf_hyperdht_find_peer_peer_relay;
static int hf_hyperdht_find_peer_peer_relay_ipv4;
static int hf_hyperdht_find_peer_peer_relay_port;

/* request/response tracking (generated) */
static int hf_hyperdht_request_in;
static int hf_hyperdht_response_in;
static int hf_hyperdht_response_time;

static int hf_hyperdht_trailing;

static int ett_hyperdht;
static int ett_hyperdht_flags;
static int ett_hyperdht_addr;
static int ett_hyperdht_value;
static int ett_hyperdht_handshake_flags;
static int ett_hyperdht_holepunch_flags;
static int ett_hyperdht_announce_flags;
static int ett_hyperdht_closer_nodes;
static int ett_hyperdht_peer_record;
static int ett_hyperdht_plugin_flags;

static expert_field ei_hyperdht_unknown_command;
static expert_field ei_hyperdht_unknown_error;
static expert_field ei_hyperdht_trailing_bytes;
static expert_field ei_hyperdht_response_missing;
static expert_field ei_hyperdht_request_missing;
static expert_field ei_hyperdht_bad_length;

static dissector_handle_t hyperdht_handle;

/* No IANA port is registered for dht-rpc, and a node falls back to an
 * ephemeral port when its configured range is unavailable (dht-rpc/lib/io.js
 * _bindSockets), so the heuristic is the primary entry point and this
 * preference exists only for deployments that pin a known port. */
#define HYPERDHT_UDP_PORTS ""

typedef struct {
    uint32_t req_frame;
    uint32_t resp_frame;
    nstime_t req_time;
    uint64_t command;
    bool     internal;
    bool     relayed;   /* slot opened by a relay forward, not a request */
} dht_request_t;

/* The map holds only the transaction a given id is currently being used for.
 * Transactions that id has already finished stay reachable through the frames
 * that resolved them, which is why the resolution happens once, on the first
 * pass, and is remembered per frame. */
typedef struct {
    wmem_map_t *pdus; /* tid -> dht_request_t */
} dht_conv_info_t;

static dht_conv_info_t *
get_dht_conv_info(conversation_t *conversation)
{
    dht_conv_info_t *dht_conv;

    dht_conv = (dht_conv_info_t *)conversation_get_proto_data(conversation, proto_hyperdht);
    if (!dht_conv) {
        dht_conv = wmem_new(wmem_file_scope(), dht_conv_info_t);
        dht_conv->pdus = wmem_map_new(wmem_file_scope(), g_direct_hash, g_direct_equal);
        conversation_add_proto_data(conversation, proto_hyperdht, dht_conv);
    }
    return dht_conv;
}

static const val64_string *
dht_command_names(bool internal)
{
    return internal ? dhtrpc_command_names : hyperdht_command_names;
}

/* Every address on this wire is the same six bytes, but each one means
 * something different, so the caller supplies the label and the three fields
 * to file it under: a filter on a relay address must not also match a closer
 * node. */
static void
add_dht_addr_item(proto_tree *tree, packet_info *pinfo, tvbuff_t *tvb, int offset,
                  const char *label, int hf_addr, int hf_ipv4, int hf_port)
{
    uint16_t    port = tvb_get_uint16(tvb, offset + 4, ENC_LITTLE_ENDIAN);
    proto_item *addr_item;
    proto_tree *addr_tree;

    addr_item = proto_tree_add_bytes_format(tree, hf_addr, tvb, offset, DHT_ADDR_LEN,
                                            NULL, "%s: %s:%u", label,
                                            tvb_ip_to_str(pinfo->pool, tvb, offset), port);
    addr_tree = proto_item_add_subtree(addr_item, ett_hyperdht_addr);
    proto_tree_add_item(addr_tree, hf_ipv4, tvb, offset, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item(addr_tree, hf_port, tvb, offset + 4, 2, ENC_LITTLE_ENDIAN);
}

/* A compact integer is up to nine bytes wide, so it is added from the decoded
 * value rather than read back from the tvb by the FT_UINT64 accessor. */
static int
add_compact_integer_item(proto_tree *tree, int hfindex, tvbuff_t *tvb, int offset,
                         compact_integer_t *num)
{
    decode_compact_integer(tvb, offset, num);
    proto_tree_add_uint64(tree, hfindex, tvb, num->offset, num->size, num->value);
    return num->size;
}

/* The item spans the data only; the length prefix belongs to the framing, not
 * to the payload the field names. */
static int
add_compact_buffer_item(proto_tree *tree, packet_info *pinfo, int hfindex, tvbuff_t *tvb,
                        int offset, int end, compact_buffer_t *buf)
{
    proto_item *item;

    decode_compact_buffer(tvb, offset, end, buf);
    item = proto_tree_add_item(tree, hfindex, tvb, buf->data_offset, buf->data_size, ENC_NA);
    if (buf->truncated)
        expert_add_info(pinfo, item, &ei_hyperdht_bad_length);

    return buf->size;
}

/* hyperdht/lib/messages.js peer.encode: fixed32 publicKey followed by a
 * compact array of ipv4 relay addresses. Returns the bytes consumed, or zero
 * when the enclosing value cannot hold another record. */
static int
add_hyperdht_peer_record(proto_tree *tree, packet_info *pinfo, tvbuff_t *tvb, int offset, int end,
                         int hf_key, int hf_relay, int hf_relay_ipv4, int hf_relay_port)
{
    compact_array_t relays;
    proto_item     *key_item;
    proto_tree     *record_tree;

    if (end - offset < DHT_KEY_LEN + 1)
        return 0;
    if (!compact_integer_fits(tvb, offset + DHT_KEY_LEN, end))
        return 0;

    key_item = proto_tree_add_item(tree, hf_key, tvb, offset, DHT_KEY_LEN, ENC_NA);
    record_tree = proto_item_add_subtree(key_item, ett_hyperdht_peer_record);

    decode_compact_array(tvb, offset + DHT_KEY_LEN, end, DHT_ADDR_LEN, &relays);
    if (relays.truncated)
        expert_add_info(pinfo, key_item, &ei_hyperdht_bad_length);

    for (int i = 0; i < relays.nelts; i++) {
        add_dht_addr_item(record_tree, pinfo, tvb, relays.data_offset + i * DHT_ADDR_LEN,
                          "Relay", hf_relay, hf_relay_ipv4, hf_relay_port);
    }

    return DHT_KEY_LEN + relays.size;
}

/* Named for the namespace, not the message: a peer_handshake mode is drawn
 * from the holepunch mode values too (hyperdht/lib/router.js). */
static void
col_append_holepunch_mode(packet_info *pinfo, uint8_t mode)
{
    col_append_fstr(pinfo->cinfo, COL_INFO, " Mode=%s",
                    val_to_str_const(mode, holepunch_mode_names, "UNKNOWN"));
}

/* dht-rpc/index.js _onrequest case PING_NAT rewrites req.from.port to the
 * advertised port before replying, so the reply arrives from this request's
 * destination addressed to the requester's host at that port. That is a
 * different five-tuple, and therefore a different conversation, from the one
 * this request belongs to; mirroring the transaction into it is what lets the
 * reply be matched back to this frame.
 *
 * The address and port arguments below are paired the way the reply will be
 * seen - the requester's address with the advertised port, this request's
 * destination with the port it was sent to - so the entry is found from either
 * direction. */
static void
track_ping_nat_reply(tvbuff_t *tvb, packet_info *pinfo, const compact_buffer_t *value,
                     dht_request_t *req)
{
    conversation_type ctype;
    conversation_t   *nat_conv;
    dht_conv_info_t  *nat_dht_conv;
    uint32_t          tid;
    uint16_t          nat_port;

    if (PINFO_FD_VISITED(pinfo))
        return;

    nat_port = tvb_get_uint16(tvb, value->data_offset, ENC_LITTLE_ENDIAN);
    if (nat_port == 0)
        return;

    ctype = conversation_pt_to_conversation_type(pinfo->ptype);
    nat_conv = find_conversation(pinfo->num, &pinfo->src, &pinfo->dst, ctype,
                                 nat_port, pinfo->destport, NO_GREEDY);
    if (!nat_conv) {
        nat_conv = conversation_new(pinfo->num, &pinfo->src, &pinfo->dst, ctype,
                                    nat_port, pinfo->destport, 0);
    }

    /* The conversation carries the transaction, not a dissector binding: the
     * reply is a bare envelope that satisfies the heuristic on its own, and the
     * heuristic claims the conversation itself once it does. */
    tid = tvb_get_uint16(tvb, DHT_TID_OFFSET, ENC_LITTLE_ENDIAN);
    nat_dht_conv = get_dht_conv_info(nat_conv);
    wmem_map_insert(nat_dht_conv->pdus, GUINT_TO_POINTER(tid), req);
}

/* dht-rpc/index.js _onrequest: each internal command reads a fixed prefix of
 * the value and ignores the request outright when the value is shorter, so a
 * short value is unusual rather than malformed. Internal replies always pass
 * a null value, which is why only requests reach here. */
static void
dissect_dhtrpc_payload(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                       const compact_buffer_t *value, uint64_t command,
                       dht_request_t *req)
{
    switch (command) {
    case DHT_CMD_PING_NAT:
        if (value->data_size < 2)
            break;
        proto_tree_add_item(tree, hf_hyperdht_ping_nat_port, tvb, value->data_offset, 2,
                            ENC_LITTLE_ENDIAN);
        track_ping_nat_reply(tvb, pinfo, value, req);
        break;

    case DHT_CMD_DOWN_HINT:
        if (value->data_size < DHT_ADDR_LEN)
            break;
        add_dht_addr_item(tree, pinfo, tvb, value->data_offset, "Node",
                          hf_hyperdht_down_hint_node, hf_hyperdht_down_hint_node_ipv4,
                          hf_hyperdht_down_hint_node_port);
        break;

    case DHT_CMD_DELAYED_PING:
        if (value->data_size < 4)
            break;
        proto_tree_add_item(tree, hf_hyperdht_delayed_ping_ms, tvb, value->data_offset, 4,
                            ENC_LITTLE_ENDIAN);
        break;

    default:
        break;
    }
}

/* hyperdht/lib/messages.js handshake.encode. The reply to a peer_handshake is
 * itself a handshake message (hyperdht/lib/router.js onpeerhandshake), so one
 * helper covers both directions. */
static void
dissect_hyperdht_peer_handshake(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                                const compact_buffer_t *value)
{
    static int * const flag_bits[] = {
        &hf_hyperdht_handshake_flag_peer,
        &hf_hyperdht_handshake_flag_relay,
        NULL
    };
    compact_buffer_t noise;
    uint8_t          hs_flags;
    int              offset = value->data_offset;

    /* handshake.preencode budgets one byte each for flags and mode, so
     * neither compact uint ever widens. */
    if (dht_value_bytes_left(value, offset) < 2)
        return;

    hs_flags = tvb_get_uint8(tvb, offset);
    proto_tree_add_bitmask(tree, tvb, offset, hf_hyperdht_handshake_flags,
                           ett_hyperdht_handshake_flags, flag_bits, ENC_NA);
    offset++;

    col_append_holepunch_mode(pinfo, tvb_get_uint8(tvb, offset));
    proto_tree_add_item(tree, hf_hyperdht_handshake_mode, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;

    if (!compact_integer_fits(tvb, offset, dht_value_end(value)))
        return;
    offset += add_compact_buffer_item(tree, pinfo, hf_hyperdht_handshake_noise, tvb,
                                      offset, dht_value_end(value), &noise);

    if (hs_flags & HYPERDHT_HANDSHAKE_FLAG_PEER) {
        if (dht_value_bytes_left(value, offset) < DHT_ADDR_LEN)
            return;
        add_dht_addr_item(tree, pinfo, tvb, offset, "Peer Address", hf_hyperdht_handshake_peer,
                          hf_hyperdht_handshake_peer_ipv4, hf_hyperdht_handshake_peer_port);
        offset += DHT_ADDR_LEN;
    }
    if (hs_flags & HYPERDHT_HANDSHAKE_FLAG_RELAY) {
        if (dht_value_bytes_left(value, offset) < DHT_ADDR_LEN)
            return;
        add_dht_addr_item(tree, pinfo, tvb, offset, "Relay Address", hf_hyperdht_handshake_relay,
                          hf_hyperdht_handshake_relay_ipv4, hf_hyperdht_handshake_relay_port);
    }
}

/* hyperdht/lib/messages.js holepunch.encode. As with the handshake, the reply
 * to a peer_holepunch is another holepunch message (hyperdht/lib/router.js
 * onpeerholepunch), so request and reply share this helper. */
static void
dissect_hyperdht_peer_holepunch(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                                const compact_buffer_t *value)
{
    static int * const flag_bits[] = {
        &hf_hyperdht_holepunch_flag_peer,
        NULL
    };
    compact_integer_t id;
    compact_buffer_t  payload;
    uint8_t           hp_flags;
    int               offset = value->data_offset;

    /* holepunch.preencode budgets two bytes for flags and mode; the id and
     * payload that follow are variable width. */
    if (dht_value_bytes_left(value, offset) < 2)
        return;

    hp_flags = tvb_get_uint8(tvb, offset);
    proto_tree_add_bitmask(tree, tvb, offset, hf_hyperdht_holepunch_flags,
                           ett_hyperdht_holepunch_flags, flag_bits, ENC_NA);
    offset++;

    col_append_holepunch_mode(pinfo, tvb_get_uint8(tvb, offset));
    proto_tree_add_item(tree, hf_hyperdht_holepunch_mode, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;

    if (!compact_integer_fits(tvb, offset, dht_value_end(value)))
        return;
    offset += add_compact_integer_item(tree, hf_hyperdht_holepunch_id, tvb, offset, &id);

    if (!compact_integer_fits(tvb, offset, dht_value_end(value)))
        return;
    offset += add_compact_buffer_item(tree, pinfo, hf_hyperdht_holepunch_payload, tvb,
                                      offset, dht_value_end(value), &payload);

    if (hp_flags & HYPERDHT_HOLEPUNCH_FLAG_PEER) {
        if (dht_value_bytes_left(value, offset) < DHT_ADDR_LEN)
            return;
        add_dht_addr_item(tree, pinfo, tvb, offset, "Peer Address", hf_hyperdht_holepunch_peer,
                          hf_hyperdht_holepunch_peer_ipv4, hf_hyperdht_holepunch_peer_port);
    }
}

/* hyperdht/lib/messages.js announce.encode, shared by announce and unannounce
 * (hyperdht/lib/persistent.js decodes both with it). */
static void
dissect_hyperdht_announce(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                          const compact_buffer_t *value)
{
    static int * const flag_bits[] = {
        &hf_hyperdht_announce_flag_peer,
        &hf_hyperdht_announce_flag_refresh,
        &hf_hyperdht_announce_flag_signature,
        &hf_hyperdht_announce_flag_bump,
        NULL
    };
    compact_integer_t bump;
    uint8_t           an_flags;
    int               offset = value->data_offset;

    /* announce.preencode reserves a single byte for the flags. */
    if (dht_value_bytes_left(value, offset) < 1)
        return;

    an_flags = tvb_get_uint8(tvb, offset);
    proto_tree_add_bitmask(tree, tvb, offset, hf_hyperdht_announce_flags,
                           ett_hyperdht_announce_flags, flag_bits, ENC_NA);
    offset++;

    if (an_flags & HYPERDHT_ANNOUNCE_FLAG_PEER) {
        int consumed = add_hyperdht_peer_record(tree, pinfo, tvb, offset, dht_value_end(value),
                                                hf_hyperdht_announce_peer,
                                                hf_hyperdht_announce_peer_relay,
                                                hf_hyperdht_announce_peer_relay_ipv4,
                                                hf_hyperdht_announce_peer_relay_port);

        if (consumed == 0)
            return;
        offset += consumed;
    }
    if (an_flags & HYPERDHT_ANNOUNCE_FLAG_REFRESH) {
        if (dht_value_bytes_left(value, offset) < DHT_REFRESH_LEN)
            return;
        proto_tree_add_item(tree, hf_hyperdht_announce_refresh, tvb, offset,
                            DHT_REFRESH_LEN, ENC_NA);
        offset += DHT_REFRESH_LEN;
    }
    if (an_flags & HYPERDHT_ANNOUNCE_FLAG_SIGNATURE) {
        if (dht_value_bytes_left(value, offset) < DHT_SIGNATURE_LEN)
            return;
        proto_tree_add_item(tree, hf_hyperdht_announce_signature, tvb, offset,
                            DHT_SIGNATURE_LEN, ENC_NA);
        offset += DHT_SIGNATURE_LEN;
    }
    if (an_flags & HYPERDHT_ANNOUNCE_FLAG_BUMP) {
        if (!compact_integer_fits(tvb, offset, dht_value_end(value)))
            return;
        add_compact_integer_item(tree, hf_hyperdht_announce_bump, tvb, offset, &bump);
    }
}

/* hyperdht/lib/messages.js mutablePutRequest.encode */
static void
dissect_hyperdht_mutable_put(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                             const compact_buffer_t *value)
{
    compact_integer_t seq;
    compact_buffer_t  data;
    int               offset = value->data_offset;

    if (dht_value_bytes_left(value, offset) < DHT_KEY_LEN)
        return;
    proto_tree_add_item(tree, hf_hyperdht_mutable_put_public_key, tvb, offset,
                        DHT_KEY_LEN, ENC_NA);
    offset += DHT_KEY_LEN;

    if (!compact_integer_fits(tvb, offset, dht_value_end(value)))
        return;
    offset += add_compact_integer_item(tree, hf_hyperdht_mutable_put_seq, tvb, offset, &seq);

    if (!compact_integer_fits(tvb, offset, dht_value_end(value)))
        return;
    offset += add_compact_buffer_item(tree, pinfo, hf_hyperdht_mutable_put_value, tvb,
                                      offset, dht_value_end(value), &data);

    if (dht_value_bytes_left(value, offset) < DHT_SIGNATURE_LEN)
        return;
    proto_tree_add_item(tree, hf_hyperdht_mutable_put_signature, tvb, offset,
                        DHT_SIGNATURE_LEN, ENC_NA);
}

/* hyperdht/lib/persistent.js decodes a mutable_get request as a bare compact
 * uint: the sequence number the requester already holds. */
static void
dissect_hyperdht_mutable_get(tvbuff_t *tvb, proto_tree *tree, const compact_buffer_t *value)
{
    compact_integer_t seq;

    if (!compact_integer_fits(tvb, value->data_offset, dht_value_end(value)))
        return;
    add_compact_integer_item(tree, hf_hyperdht_mutable_get_req_seq, tvb,
                             value->data_offset, &seq);
}

/* hyperdht/lib/messages.js mutableGetResponse.encode */
static void
dissect_hyperdht_mutable_get_reply(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                                   const compact_buffer_t *value)
{
    compact_integer_t seq;
    compact_buffer_t  data;
    int               offset = value->data_offset;

    if (!compact_integer_fits(tvb, offset, dht_value_end(value)))
        return;
    offset += add_compact_integer_item(tree, hf_hyperdht_mutable_get_resp_seq, tvb,
                                       offset, &seq);

    if (!compact_integer_fits(tvb, offset, dht_value_end(value)))
        return;
    offset += add_compact_buffer_item(tree, pinfo, hf_hyperdht_mutable_get_resp_value, tvb,
                                      offset, dht_value_end(value), &data);

    if (dht_value_bytes_left(value, offset) < DHT_SIGNATURE_LEN)
        return;
    proto_tree_add_item(tree, hf_hyperdht_mutable_get_resp_signature, tvb, offset,
                        DHT_SIGNATURE_LEN, ENC_NA);
}

/* hyperdht/lib/messages.js lookupRawReply: a compact array of peer records
 * followed by a bump that the decoder reads only if bytes remain. */
static void
dissect_hyperdht_lookup_reply(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                              const compact_buffer_t *value)
{
    compact_integer_t count, bump;
    int               offset = value->data_offset;

    if (!compact_integer_fits(tvb, offset, dht_value_end(value)))
        return;
    offset += add_compact_integer_item(tree, hf_hyperdht_lookup_peer_count, tvb,
                                       offset, &count);

    for (uint64_t i = 0; i < count.value; i++) {
        /* The count is a 64-bit wire value, so the loop stops at the first
         * record the value has no room for rather than trusting it. */
        int consumed = add_hyperdht_peer_record(tree, pinfo, tvb, offset, dht_value_end(value),
                                                hf_hyperdht_lookup_peer,
                                                hf_hyperdht_lookup_peer_relay,
                                                hf_hyperdht_lookup_peer_relay_ipv4,
                                                hf_hyperdht_lookup_peer_relay_port);

        if (consumed == 0) {
            proto_tree_add_expert(tree, pinfo, &ei_hyperdht_bad_length,
                                  tvb, offset, 0);
            break;
        }
        offset += consumed;
    }

    if (compact_integer_fits(tvb, offset, dht_value_end(value)))
        add_compact_integer_item(tree, hf_hyperdht_lookup_bump, tvb, offset, &bump);
}

/* hyperdht/lib/messages.js pluginRequest.encode. A compact string is framed
 * exactly like a compact buffer, so the same decoder covers the name. */
static void
dissect_hyperdht_plugin_request(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                                const compact_buffer_t *value)
{
    static int * const flag_bits[] = {
        &hf_hyperdht_plugin_flag_value,
        NULL
    };
    compact_buffer_t  name, data;
    compact_integer_t version, command;
    proto_item       *name_item;
    uint8_t           pl_flags;
    int               offset = value->data_offset;

    if (!compact_integer_fits(tvb, offset, dht_value_end(value)))
        return;
    decode_compact_buffer(tvb, offset, dht_value_end(value), &name);
    name_item = proto_tree_add_item(tree, hf_hyperdht_plugin_name, tvb, name.data_offset,
                                    name.data_size, ENC_UTF_8);
    if (name.truncated) {
        expert_add_info(pinfo, name_item, &ei_hyperdht_bad_length);
        return;
    }
    offset += name.size;

    if (!compact_integer_fits(tvb, offset, dht_value_end(value)))
        return;
    offset += add_compact_integer_item(tree, hf_hyperdht_plugin_version, tvb, offset, &version);

    if (!compact_integer_fits(tvb, offset, dht_value_end(value)))
        return;
    offset += add_compact_integer_item(tree, hf_hyperdht_plugin_command, tvb, offset, &command);

    /* pluginRequest.preencode reserves one byte for the flags. */
    if (dht_value_bytes_left(value, offset) < 1)
        return;
    pl_flags = tvb_get_uint8(tvb, offset);
    proto_tree_add_bitmask(tree, tvb, offset, hf_hyperdht_plugin_flags,
                           ett_hyperdht_plugin_flags, flag_bits, ENC_NA);
    offset++;

    if (pl_flags & HYPERDHT_PLUGIN_FLAG_VALUE) {
        if (!compact_integer_fits(tvb, offset, dht_value_end(value)))
            return;
        add_compact_buffer_item(tree, pinfo, hf_hyperdht_plugin_value, tvb, offset,
                                dht_value_end(value), &data);
    }
}

static void
dissect_hyperdht_payload(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                         const compact_buffer_t *value, uint64_t command, bool request)
{
    switch (command) {
    case HYPERDHT_CMD_PEER_HANDSHAKE:
        dissect_hyperdht_peer_handshake(tvb, pinfo, tree, value);
        break;

    case HYPERDHT_CMD_PEER_HOLEPUNCH:
        dissect_hyperdht_peer_holepunch(tvb, pinfo, tree, value);
        break;

    case HYPERDHT_CMD_FIND_PEER:
        /* The request carries no value (hyperdht/index.js findPeer sends
         * value: null; the target rides the envelope target field). The
         * reply is a peer record (hyperdht/lib/persistent.js onfindpeer). */
        if (!request)
            add_hyperdht_peer_record(tree, pinfo, tvb, value->data_offset, dht_value_end(value),
                                     hf_hyperdht_find_peer_peer, hf_hyperdht_find_peer_peer_relay,
                                     hf_hyperdht_find_peer_peer_relay_ipv4,
                                     hf_hyperdht_find_peer_peer_relay_port);
        break;

    case HYPERDHT_CMD_LOOKUP:
        if (!request)
            dissect_hyperdht_lookup_reply(tvb, pinfo, tree, value);
        break;

    case HYPERDHT_CMD_ANNOUNCE:
    case HYPERDHT_CMD_UNANNOUNCE:
        if (request)
            dissect_hyperdht_announce(tvb, pinfo, tree, value);
        break;

    case HYPERDHT_CMD_MUTABLE_PUT:
        if (request)
            dissect_hyperdht_mutable_put(tvb, pinfo, tree, value);
        break;

    case HYPERDHT_CMD_MUTABLE_GET:
        if (request)
            dissect_hyperdht_mutable_get(tvb, tree, value);
        else
            dissect_hyperdht_mutable_get_reply(tvb, pinfo, tree, value);
        break;

    case HYPERDHT_CMD_IMMUTABLE_PUT:
        if (request)
            proto_tree_add_item(tree, hf_hyperdht_immutable_value, tvb,
                                value->data_offset, value->data_size, ENC_NA);
        break;

    case HYPERDHT_CMD_IMMUTABLE_GET:
        if (!request)
            proto_tree_add_item(tree, hf_hyperdht_immutable_value, tvb,
                                value->data_offset, value->data_size, ENC_NA);
        break;

    case HYPERDHT_CMD_PLUGIN:
        /* A plugin answers through the ordinary dht-rpc reply path and
         * hyperdht/lib/plugin.js defines no response encoding, so the reply
         * value stays opaque. */
        if (request)
            dissect_hyperdht_plugin_request(tvb, pinfo, tree, value);
        else
            proto_tree_add_item(tree, hf_hyperdht_plugin_resp_value, tvb,
                                value->data_offset, value->data_size, ENC_NA);
        break;

    default:
        break;
    }
}

static int
add_dht_value_item(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset,
                   compact_buffer_t *value, proto_tree **value_tree)
{
    proto_item *value_item;

    decode_compact_buffer(tvb, offset, tvb_reported_length(tvb), value);
    value_item = proto_tree_add_item(tree, hf_hyperdht_value, tvb, value->offset,
                                     value->size, ENC_NA);
    *value_tree = proto_item_add_subtree(value_item, ett_hyperdht_value);

    /* Reachable through a claimed conversation or a forced decode; first
     * contact with a truncated value is rejected by the heuristic. */
    if (value->truncated)
        expert_add_info(pinfo, value_item, &ei_hyperdht_bad_length);

    return value->size;
}

static int
add_dht_closer_nodes_item(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset)
{
    compact_array_t nodes;
    proto_item     *nodes_item;
    proto_tree     *nodes_tree;

    decode_compact_array(tvb, offset, tvb_reported_length(tvb), DHT_ADDR_LEN, &nodes);
    nodes_item = proto_tree_add_item(tree, hf_hyperdht_closer_nodes, tvb, nodes.offset,
                                     nodes.size, ENC_NA);
    proto_item_append_text(nodes_item, " (%" PRIu64 " nodes)", nodes.declared_nelts);
    nodes_tree = proto_item_add_subtree(nodes_item, ett_hyperdht_closer_nodes);

    /* Reachable as at the value item: claimed conversation or forced decode. */
    if (nodes.truncated)
        expert_add_info(pinfo, nodes_item, &ei_hyperdht_bad_length);

    for (int i = 0; i < nodes.nelts; i++) {
        add_dht_addr_item(nodes_tree, pinfo, tvb, nodes.data_offset + i * DHT_ADDR_LEN,
                          "Closer Node", hf_hyperdht_closer_node,
                          hf_hyperdht_closer_node_ipv4, hf_hyperdht_closer_node_port);
    }

    return nodes.size;
}

static int
dissect_hyperdht_request(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset,
                         uint8_t flags, bool internal, dht_request_t *req)
{
    compact_integer_t command;
    compact_buffer_t  value;
    proto_tree       *value_tree;
    proto_item       *command_item;
    const char       *command_name;

    offset += decode_compact_integer(tvb, offset, &command);
    if (!PINFO_FD_VISITED(pinfo)) {
        req->command = command.value;
        req->internal = internal;
    }

    command_name = try_val64_to_str(command.value, dht_command_names(internal));
    command_item = proto_tree_add_uint64(tree,
            internal ? hf_hyperdht_dhtrpc_command : hf_hyperdht_command,
            tvb, command.offset, command.size, command.value);
    if (command_name == NULL)
        expert_add_info(pinfo, command_item, &ei_hyperdht_unknown_command);

    if (command_name)
        col_add_fstr(pinfo->cinfo, COL_INFO, "Req %s", command_name);
    else
        col_add_fstr(pinfo->cinfo, COL_INFO, "Req UNKNOWN (%" PRIu64 ")", command.value);

    if (flags & DHT_REQ_FLAG_TARGET) {
        proto_tree_add_item(tree, hf_hyperdht_target, tvb, offset, DHT_TARGET_LEN, ENC_NA);
        offset += DHT_TARGET_LEN;
    }

    if (flags & DHT_FLAG_VALUE) {
        offset += add_dht_value_item(tvb, pinfo, tree, offset, &value, &value_tree);
        if (internal)
            dissect_dhtrpc_payload(tvb, pinfo, value_tree, &value, command.value, req);
        else
            dissect_hyperdht_payload(tvb, pinfo, value_tree, &value, command.value, true);
    }

    return offset;
}

static int
dissect_hyperdht_response(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset,
                          uint8_t flags, const dht_request_t *req)
{
    compact_buffer_t value;
    proto_tree      *value_tree;

    /* A reply names neither its command nor its target (dht-rpc/lib/io.js
     * _sendReply), so everything below the envelope depends on having seen
     * the request that shares this transaction id. */
    if (req->req_frame) {
        const char *command_name = try_val64_to_str(req->command,
                                                    dht_command_names(req->internal));

        if (command_name)
            col_add_fstr(pinfo->cinfo, COL_INFO, "Reply %s", command_name);
        else
            col_add_fstr(pinfo->cinfo, COL_INFO, "Reply UNKNOWN (%" PRIu64 ")",
                         req->command);
    } else {
        col_set_str(pinfo->cinfo, COL_INFO, "Reply (Request not seen)");
    }

    if (flags & DHT_RESP_FLAG_CLOSER)
        offset += add_dht_closer_nodes_item(tvb, pinfo, tree, offset);

    if (flags & DHT_RESP_FLAG_ERROR) {
        compact_integer_t error;
        proto_item       *error_item;
        const char       *error_name;

        offset += decode_compact_integer(tvb, offset, &error);
        error_name = try_val64_to_str(error.value, dht_error_names);
        error_item = proto_tree_add_uint64(tree, hf_hyperdht_error, tvb, error.offset,
                                           error.size, error.value);
        if (error_name == NULL)
            expert_add_info(pinfo, error_item, &ei_hyperdht_unknown_error);

        if (error_name)
            col_append_fstr(pinfo->cinfo, COL_INFO, " Error=%s", error_name);
        else
            col_append_fstr(pinfo->cinfo, COL_INFO, " Error=UNKNOWN (%" PRIu64 ")",
                            error.value);
    }

    if (flags & DHT_FLAG_VALUE) {
        offset += add_dht_value_item(tvb, pinfo, tree, offset, &value, &value_tree);

        /* dht-rpc/index.js _onrequest answers every internal command with a
         * null value, so an internal reply has no payload to decode. */
        if (req->req_frame && !req->internal)
            dissect_hyperdht_payload(tvb, pinfo, value_tree, &value, req->command, false);
    }

    return offset;
}

/* How a message takes part in a transaction. A PEER_HANDSHAKE or
 * PEER_HOLEPUNCH request is answered with a dht-rpc response on its own
 * conversation only when its mode is FROM_CLIENT: every other leg of the
 * relay round is forwarded to the next hop as a fresh request under the same
 * transaction id (dht-rpc/lib/io.js relay), so on the relay-server
 * conversation the FROM_SERVER request is the answer to the FROM_RELAY
 * request, and a handshake routed over a second relay sends its answer to a
 * third node entirely (hyperdht/lib/router.js onpeerhandshake,
 * onpeerholepunch). */
typedef enum {
    DHT_ROLE_REQUEST,       /* answered by a response on this conversation */
    DHT_ROLE_RESPONSE,      /* the response that answers one */
    DHT_ROLE_RELAY_FORWARD, /* answered by a relayed request, never a response */
    DHT_ROLE_RELAY_ANSWER,  /* the relayed request that answers a forward */
    DHT_ROLE_UNANSWERED     /* nothing comes back on this conversation */
} dht_role_t;

/* Sort a request into its transaction role without touching the tree. Reads
 * are bounded by the captured length, as in the heuristic, so a short capture
 * degrades gracefully instead of throwing before the tree exists. Every exit
 * that could not positively read a mode falls back to DHT_ROLE_REQUEST: a
 * value this capture is missing was still on the wire for the peer, so the
 * ordinary bookkeeping - and the reply that may well be in the capture -
 * must go on working. */
static dht_role_t
dht_request_role(tvbuff_t *tvb, uint8_t flags)
{
    compact_integer_t command;
    compact_buffer_t  value;
    int               len = tvb_captured_length(tvb);
    int               offset = DHT_HEADER_LEN;

    if (flags & DHT_REQ_FLAG_INTERNAL)
        return DHT_ROLE_REQUEST;

    if (flags & DHT_FLAG_ID)
        offset += DHT_ID_LEN;
    if (flags & DHT_FLAG_TOKEN)
        offset += DHT_TOKEN_LEN;

    if (!compact_integer_present(tvb, offset))
        return DHT_ROLE_REQUEST;
    offset += decode_compact_integer(tvb, offset, &command);

    if (command.value != HYPERDHT_CMD_PEER_HANDSHAKE &&
        command.value != HYPERDHT_CMD_PEER_HOLEPUNCH)
        return DHT_ROLE_REQUEST;

    if (!(flags & DHT_FLAG_VALUE))
        return DHT_ROLE_REQUEST;
    if (flags & DHT_REQ_FLAG_TARGET)
        offset += DHT_TARGET_LEN;
    if (!compact_integer_present(tvb, offset))
        return DHT_ROLE_REQUEST;
    decode_compact_buffer(tvb, offset, len, &value);
    if (value.truncated || value.data_size < 2)
        return DHT_ROLE_REQUEST;

    /* messages.js handshake.encode and holepunch.encode both start the value
     * with a flags byte followed by the mode. */
    switch (tvb_get_uint8(tvb, value.data_offset + 1)) {
    case HYPERDHT_MODE_FROM_CLIENT:
        return DHT_ROLE_REQUEST;
    case HYPERDHT_MODE_FROM_RELAY:
        return DHT_ROLE_RELAY_FORWARD;
    case HYPERDHT_MODE_FROM_SERVER:
        return DHT_ROLE_RELAY_ANSWER;
    case HYPERDHT_MODE_FROM_SECOND_RELAY:
    case HYPERDHT_MODE_REPLY:
        /* Answered toward a third node (router.js onpeerhandshake
         * FROM_SECOND_RELAY), or a mode a request never carries. */
        return DHT_ROLE_UNANSWERED;
    default:
        return DHT_ROLE_REQUEST;
    }
}

/* A transaction id does not identify a transaction for the length of a
 * capture: dht-rpc resends a request under the same id up to three times
 * (dht-rpc/lib/io.js Request.retries, oncycle) and hands out ids from a counter
 * that wraps at 65536 (io.js createRequest), so a lookup by id alone finds
 * whichever transaction held the slot last. Each frame therefore resolves its
 * transaction once, on the first pass, and remembers the result. */
static dht_request_t *
dht_track_transaction(packet_info *pinfo, dht_conv_info_t *dht_conv, uint32_t tid,
                      dht_role_t role)
{
    dht_request_t *req;

    if (PINFO_FD_VISITED(pinfo)) {
        req = (dht_request_t *)p_get_proto_data(wmem_file_scope(), pinfo, proto_hyperdht, 0);
    } else if (role == DHT_ROLE_UNANSWERED) {
        /* Nothing pairs with this frame, so it neither starts a transaction
         * nor closes one an unrelated exchange still has in flight. */
        req = NULL;
    } else {
        req = (dht_request_t *)wmem_map_lookup(dht_conv->pdus, GUINT_TO_POINTER(tid));

        if (role == DHT_ROLE_REQUEST || role == DHT_ROLE_RELAY_FORWARD) {
            /* A slot that already has its reply belongs to a transaction that
             * is over, so the id has come round again and this request starts
             * a new one. A slot still waiting for a reply is this same request
             * being resent: keeping the first attempt's frame and timestamp is
             * what makes the response time span the whole exchange. Only a
             * slot of the same kind can be a resend, though - a declined
             * forward is never resolved, so its slot would otherwise wait to
             * adopt whatever ordinary request reuses the id, days later. */
            if (!req || req->resp_frame ||
                req->relayed != (role == DHT_ROLE_RELAY_FORWARD)) {
                req = wmem_new0(wmem_file_scope(), dht_request_t);
                req->req_frame = pinfo->num;
                req->req_time = pinfo->fd->abs_ts;
                req->relayed = (role == DHT_ROLE_RELAY_FORWARD);
                wmem_map_insert(dht_conv->pdus, GUINT_TO_POINTER(tid), req);
            }
        } else if (role == DHT_ROLE_RELAY_ANSWER && (!req || !req->relayed)) {
            /* A FROM_SERVER leg answers only a forward. A slot an ordinary
             * request opened under the same reused id is not this frame's
             * transaction, so it stays untouched and unclaimed. The reverse
             * pairing is legitimate, though: a forward can be closed by a
             * real error response, from a node that does not know the
             * command (dht-rpc/index.js _onrequest). */
            req = NULL;
        } else if (req && req->resp_frame == 0) {
            /* A duplicated reply keeps the first frame: response time is
             * measured against the reply that ended the transaction. */
            req->resp_frame = pinfo->num;
        }

        if (req)
            p_add_proto_data(wmem_file_scope(), pinfo, proto_hyperdht, 0, req);
    }

    if (!req) {
        /* Nothing is known about this transaction - the request was not
         * captured, or the capture started mid-flow. A packet-scope stand-in
         * keeps the rest of the dissection branch-free. */
        req = wmem_new0(pinfo->pool, dht_request_t);
        req->req_time = pinfo->fd->abs_ts;
    }

    return req;
}

static void
add_transaction_links(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *ti,
                      dht_role_t role, const dht_request_t *req)
{
    proto_item *it;

    if (role == DHT_ROLE_UNANSWERED)
        return;

    if (role == DHT_ROLE_REQUEST || role == DHT_ROLE_RELAY_FORWARD) {
        if (req->resp_frame) {
            it = proto_tree_add_uint(tree, hf_hyperdht_response_in, tvb, 0, 0,
                                     req->resp_frame);
            proto_item_set_generated(it);
        } else if (role == DHT_ROLE_REQUEST && PINFO_FD_VISITED(pinfo)) {
            /* Until the first pass has run to the end of the capture, a reply
             * that has not been reached yet is indistinguishable from one
             * that was never sent. A relay forward with no answer stays
             * quiet instead: a server that declines a handshake or holepunch
             * sends nothing back (hyperdht/lib/router.js returns without
             * replying), so an unanswered forward is normal traffic. */
            expert_add_info(pinfo, ti, &ei_hyperdht_response_missing);
        }
        return;
    }

    /* req_frame <= num: in an out-of-order capture the mirrored request can
     * sit on a later frame, and a backwards link with a negative response
     * time would be nonsense, so treat it as unmatched. */
    if (req->req_frame && req->req_frame <= pinfo->num) {
        nstime_t ns;

        it = proto_tree_add_uint(tree, hf_hyperdht_request_in, tvb, 0, 0, req->req_frame);
        proto_item_set_generated(it);

        nstime_delta(&ns, &pinfo->fd->abs_ts, &req->req_time);
        it = proto_tree_add_time(tree, hf_hyperdht_response_time, tvb, 0, 0, &ns);
        proto_item_set_generated(it);
    } else if (role == DHT_ROLE_RESPONSE) {
        /* A FROM_SERVER answer routed over a second relay arrives on a
         * conversation that never carried the forward (router.js
         * onpeerhandshake FROM_SECOND_RELAY), so only a true response is
         * worth a missing-request note. */
        expert_add_info(pinfo, ti, &ei_hyperdht_request_missing);
    }
}

static int
dissect_hyperdht(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    static int * const req_bits[] = {
        &hf_hyperdht_flag_id,
        &hf_hyperdht_flag_token,
        &hf_hyperdht_flag_internal,
        &hf_hyperdht_flag_target,
        &hf_hyperdht_flag_value,
        NULL
    };
    static int * const resp_bits[] = {
        &hf_hyperdht_flag_id,
        &hf_hyperdht_flag_token,
        &hf_hyperdht_flag_closer_nodes,
        &hf_hyperdht_flag_error,
        &hf_hyperdht_flag_value,
        NULL
    };
    proto_item      *ti;
    proto_tree      *hyperdht_tree;
    conversation_t  *conversation;
    dht_conv_info_t *dht_conv;
    dht_request_t   *req;
    dht_role_t       role;
    uint8_t          b0, flags;
    uint32_t         tid;
    bool             request, internal;
    int              offset, trailing;

    /* First contact is vetted by the strict heuristic. This function is
     * reached through a claimed conversation, the UDP port preference or
     * Decode As, so only a minimal envelope check applies here - unknown
     * commands and trailing bytes must still dissect and still raise their
     * expert items. */
    if (tvb_reported_length(tvb) < DHT_HEADER_LEN)
        return 0;
    b0 = tvb_get_uint8(tvb, DHT_TYPE_OFFSET);
    if (b0 != DHT_RPC_REQUEST_ID && b0 != DHT_RPC_RESPONSE_ID)
        return 0;
    /* The peer reads the flags with c.uint (dht-rpc/lib/io.js decodeReply), so
     * a byte above 0xfc widens and desynchronizes every later offset, and the
     * encoder never sets a bit outside the defined five. */
    flags = tvb_get_uint8(tvb, DHT_FLAGS_OFFSET);
    if (flags & ~DHT_FLAG_MASK)
        return 0;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "HyperDHT");
    col_clear(pinfo->cinfo, COL_INFO);

    request = (b0 == DHT_RPC_REQUEST_ID);
    internal = request && (flags & DHT_REQ_FLAG_INTERNAL);
    tid = tvb_get_uint16(tvb, DHT_TID_OFFSET, ENC_LITTLE_ENDIAN);
    role = request ? dht_request_role(tvb, flags) : DHT_ROLE_RESPONSE;

    conversation = find_or_create_conversation(pinfo);
    dht_conv = get_dht_conv_info(conversation);
    req = dht_track_transaction(pinfo, dht_conv, tid, role);

    ti = proto_tree_add_item(tree, proto_hyperdht, tvb, 0, -1, ENC_NA);
    hyperdht_tree = proto_item_add_subtree(ti, ett_hyperdht);

    proto_tree_add_item(hyperdht_tree, hf_hyperdht_response, tvb, DHT_TYPE_OFFSET, 1,
                        ENC_BIG_ENDIAN);
    proto_tree_add_item(hyperdht_tree, hf_hyperdht_version, tvb, DHT_TYPE_OFFSET, 1,
                        ENC_BIG_ENDIAN);
    proto_tree_add_bitmask(hyperdht_tree, tvb, DHT_FLAGS_OFFSET, hf_hyperdht_flags,
                           ett_hyperdht_flags, request ? req_bits : resp_bits, ENC_NA);
    proto_tree_add_item(hyperdht_tree, hf_hyperdht_tid, tvb, DHT_TID_OFFSET, 2,
                        ENC_LITTLE_ENDIAN);
    add_dht_addr_item(hyperdht_tree, pinfo, tvb, DHT_ADDR_OFFSET, "Peer", hf_hyperdht_peer,
                      hf_hyperdht_peer_ipv4, hf_hyperdht_peer_port);
    offset = DHT_HEADER_LEN;

    if (flags & DHT_FLAG_ID) {
        proto_tree_add_item(hyperdht_tree, hf_hyperdht_id, tvb, offset, DHT_ID_LEN, ENC_NA);
        offset += DHT_ID_LEN;
    }
    if (flags & DHT_FLAG_TOKEN) {
        proto_tree_add_item(hyperdht_tree, hf_hyperdht_token, tvb, offset, DHT_TOKEN_LEN,
                            ENC_NA);
        offset += DHT_TOKEN_LEN;
    }

    if (request)
        offset = dissect_hyperdht_request(tvb, pinfo, hyperdht_tree, offset, flags,
                                          internal, req);
    else
        offset = dissect_hyperdht_response(tvb, pinfo, hyperdht_tree, offset, flags, req);

    add_transaction_links(tvb, pinfo, hyperdht_tree, ti, role, req);

    /* The encoder emits exactly the fields above and nothing else, so bytes
     * past this offset were not put there by a dht-rpc peer. */
    trailing = tvb_reported_length_remaining(tvb, offset);
    if (trailing > 0) {
        proto_item *it = proto_tree_add_item(hyperdht_tree, hf_hyperdht_trailing, tvb,
                                             offset, trailing, ENC_NA);

        expert_add_info(pinfo, it, &ei_hyperdht_trailing_bytes);
    }

    return tvb_reported_length(tvb);
}

/* The dht-rpc address field is the address the sender transmitted to, so it is
 * always a real unicast host and port. Loopback is deliberately accepted:
 * local testnets bootstrap on 127.0.0.1 and put it on the wire here. */
static bool
dht_addr_plausible(tvbuff_t *tvb, int offset)
{
    uint32_t ipv4 = tvb_get_uint32(tvb, offset, ENC_BIG_ENDIAN);

    if (tvb_get_uint16(tvb, offset + 4, ENC_LITTLE_ENDIAN) == 0)
        return false;
    if ((ipv4 >> 24) == 0)      /* 0.0.0.0/8 */
        return false;
    if (ipv4 >= 0xe0000000)     /* multicast, reserved, broadcast */
        return false;

    return true;
}

/* Envelope layout and compact-encoding rules are used to reject non-HyperDHT
 * traffic before the conversation is claimed.
 *
 * Unlike the main dissection path, which parses against the reported length
 * and lets the tvb layer throw on a short capture, everything here is measured
 * against the captured length and guarded by tvb_bytes_exist: a heuristic must
 * return false rather than throw (README.heuristic). A consequence of the
 * exact-length check below is that snaplen-truncated captures are never
 * claimed heuristically and need Decode As or the port preference - deliberate,
 * since a partial envelope cannot be told apart from foreign traffic. */
static bool
test_hyperdht_packet(tvbuff_t *tvb)
{
    int     len = tvb_captured_length(tvb);
    uint8_t b0, flags;
    int     offset, need;
    bool    request;

    if (len < DHT_HEADER_LEN)
        return false;

    b0 = tvb_get_uint8(tvb, DHT_TYPE_OFFSET);
    if (b0 != DHT_RPC_REQUEST_ID && b0 != DHT_RPC_RESPONSE_ID)
        return false;

    flags = tvb_get_uint8(tvb, DHT_FLAGS_OFFSET);
    if (flags & ~DHT_FLAG_MASK)
        return false;

    if (!dht_addr_plausible(tvb, DHT_ADDR_OFFSET))
        return false;

    request = (b0 == DHT_RPC_REQUEST_ID);

    need = DHT_HEADER_LEN;
    if (flags & DHT_FLAG_ID)
        need += DHT_ID_LEN;
    if (flags & DHT_FLAG_TOKEN)
        need += DHT_TOKEN_LEN;
    if (len < need)
        return false;

    offset = need;

    if (request) {
        compact_integer_t command;

        /* Every defined command is a single byte, but the encoder writes a
         * compact uint, so a wider encoding is legal and is bounds-checked
         * rather than rejected outright. */
        if (!compact_integer_present(tvb, offset))
            return false;
        offset += decode_compact_integer(tvb, offset, &command);

        /* First contact has nothing else to go on, so require a command this
         * dissector knows. Unknown commands are still dissected, and still
         * raise ei_hyperdht_unknown_command, once the conversation has been
         * claimed or when the UDP port preference is set. */
        if (try_val64_to_str(command.value,
                             dht_command_names((flags & DHT_REQ_FLAG_INTERNAL) != 0)) == NULL)
            return false;

        if (flags & DHT_REQ_FLAG_TARGET) {
            if (!tvb_bytes_exist(tvb, offset, DHT_TARGET_LEN))
                return false;
            offset += DHT_TARGET_LEN;
        }
    } else {
        if (flags & DHT_RESP_FLAG_CLOSER) {
            compact_array_t closer_nodes;

            if (!compact_integer_present(tvb, offset))
                return false;
            decode_compact_array(tvb, offset, len, DHT_ADDR_LEN, &closer_nodes);
            if (closer_nodes.truncated)
                return false;
            offset += closer_nodes.size;
        }
        if (flags & DHT_RESP_FLAG_ERROR) {
            compact_integer_t error;

            if (!compact_integer_present(tvb, offset))
                return false;
            offset += decode_compact_integer(tvb, offset, &error);
            if (try_val64_to_str(error.value, dht_error_names) == NULL)
                return false;
        }
    }

    if (flags & DHT_FLAG_VALUE) {
        compact_buffer_t value;

        if (!compact_integer_present(tvb, offset))
            return false;
        decode_compact_buffer(tvb, offset, len, &value);
        if (value.truncated)
            return false;
        offset += value.size;
    }

    /* The encoder (dht-rpc/lib/io.js) emits exactly these fields and nothing
     * else, so a message that does not end here is not one of ours. Frames
     * with trailing bytes still dissect - and still raise the trailing-bytes
     * expert item - once the conversation has been claimed. */
    return offset == len;
}

static bool
dissect_hyperdht_heur(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
    conversation_t *udp_conversation;

    if (!test_hyperdht_packet(tvb))
        return false;

    udp_conversation = find_or_create_conversation(pinfo);
    conversation_set_dissector(udp_conversation, hyperdht_handle);

    return dissect_hyperdht(tvb, pinfo, tree, data) > 0;
}

void
proto_register_hyperdht(void)
{
    expert_module_t *expert_hyperdht;

    static hf_register_info hf[] = {
        { &hf_hyperdht_response,
          { "Response", "hyperdht.response", FT_BOOLEAN, 8,
            NULL, DHT_TYPE_RESPONSE, "Whether this message is a response", HFILL } },
        { &hf_hyperdht_version,
          { "Protocol Version", "hyperdht.version", FT_UINT8, BASE_DEC,
            NULL, DHT_TYPE_VERSION, NULL, HFILL } },
        { &hf_hyperdht_flags,
          { "Flags", "hyperdht.flags", FT_UINT8, BASE_HEX,
            NULL, 0x0, NULL, HFILL } },
        { &hf_hyperdht_flag_id,
          { "ID", "hyperdht.flag.id", FT_BOOLEAN, 8,
            NULL, DHT_FLAG_ID, "Whether the node id field is present", HFILL } },
        { &hf_hyperdht_flag_token,
          { "Token", "hyperdht.flag.token", FT_BOOLEAN, 8,
            NULL, DHT_FLAG_TOKEN, "Whether the token field is present", HFILL } },
        { &hf_hyperdht_flag_internal,
          { "Internal", "hyperdht.flag.internal", FT_BOOLEAN, 8,
            NULL, DHT_REQ_FLAG_INTERNAL, "Whether this is a dht-rpc internal command", HFILL } },
        { &hf_hyperdht_flag_closer_nodes,
          { "Closer Nodes", "hyperdht.flag.closer_nodes", FT_BOOLEAN, 8,
            NULL, DHT_RESP_FLAG_CLOSER, "Whether the closer nodes array is present", HFILL } },
        { &hf_hyperdht_flag_target,
          { "Target", "hyperdht.flag.target", FT_BOOLEAN, 8,
            NULL, DHT_REQ_FLAG_TARGET, "Whether the target field is present", HFILL } },
        { &hf_hyperdht_flag_error,
          { "Error", "hyperdht.flag.error", FT_BOOLEAN, 8,
            NULL, DHT_RESP_FLAG_ERROR, "Whether the error field is present", HFILL } },
        { &hf_hyperdht_flag_value,
          { "Value", "hyperdht.flag.value", FT_BOOLEAN, 8,
            NULL, DHT_FLAG_VALUE, "Whether the value field is present", HFILL } },
        { &hf_hyperdht_tid,
          { "Transaction ID", "hyperdht.transaction_id", FT_UINT16, BASE_DEC,
            NULL, 0x0, NULL, HFILL } },
        { &hf_hyperdht_peer,
          { "Peer", "hyperdht.peer", FT_BYTES, BASE_NONE,
            NULL, 0x0, "Address the message was transmitted to", HFILL } },
        { &hf_hyperdht_peer_ipv4,
          { "IPv4 Address", "hyperdht.peer.ipv4", FT_IPv4, BASE_NONE,
            NULL, 0x0, NULL, HFILL } },
        { &hf_hyperdht_peer_port,
          { "Port", "hyperdht.peer.port", FT_UINT16, BASE_DEC,
            NULL, 0x0, NULL, HFILL } },
        { &hf_hyperdht_id,
          { "Node ID", "hyperdht.id", FT_BYTES, BASE_NONE,
            NULL, 0x0, NULL, HFILL } },
        { &hf_hyperdht_token,
          { "Token", "hyperdht.token", FT_BYTES, BASE_NONE,
            NULL, 0x0, NULL, HFILL } },
        /* One filter name on purpose: hyperdht.command == "PING" and
         * hyperdht.command == "FIND_PEER" both work without the reader
         * knowing which of the two command namespaces (the internal-flag
         * split) a name lives in. The first entry's blurb speaks for both,
         * because the field list keeps only the first of a shared name. */
        { &hf_hyperdht_command,
          { "Command", "hyperdht.command", FT_UINT64, BASE_DEC | BASE_VAL64_STRING,
            VALS64(hyperdht_command_names), 0x0,
            "HyperDHT or dht-rpc internal command", HFILL } },
        { &hf_hyperdht_dhtrpc_command,
          { "Command", "hyperdht.command", FT_UINT64, BASE_DEC | BASE_VAL64_STRING,
            VALS64(dhtrpc_command_names), 0x0, "dht-rpc internal command", HFILL } },
        { &hf_hyperdht_target,
          { "Target", "hyperdht.target", FT_BYTES, BASE_NONE,
            NULL, 0x0, NULL, HFILL } },
        { &hf_hyperdht_value,
          { "Value", "hyperdht.value", FT_BYTES, BASE_NONE,
            NULL, 0x0, NULL, HFILL } },
        { &hf_hyperdht_error,
          { "Error", "hyperdht.error", FT_UINT64, BASE_DEC | BASE_VAL64_STRING,
            VALS64(dht_error_names), 0x0, NULL, HFILL } },
        { &hf_hyperdht_closer_nodes,
          { "Closer Nodes", "hyperdht.closer_nodes", FT_BYTES, BASE_NONE,
            NULL, 0x0, NULL, HFILL } },
        { &hf_hyperdht_closer_node,
          { "Closer Node", "hyperdht.closer_nodes.node", FT_BYTES, BASE_NONE,
            NULL, 0x0, NULL, HFILL } },
        { &hf_hyperdht_closer_node_ipv4,
          { "IPv4 Address", "hyperdht.closer_nodes.node.ipv4", FT_IPv4, BASE_NONE,
            NULL, 0x0, NULL, HFILL } },
        { &hf_hyperdht_closer_node_port,
          { "Port", "hyperdht.closer_nodes.node.port", FT_UINT16, BASE_DEC,
            NULL, 0x0, NULL, HFILL } },

        { &hf_hyperdht_ping_nat_port,
          { "NAT Port", "hyperdht.ping_nat.port", FT_UINT16, BASE_DEC,
            NULL, 0x0, "Port the PING_NAT reply should be sent to", HFILL } },
        { &hf_hyperdht_down_hint_node,
          { "Node", "hyperdht.down_hint.node", FT_BYTES, BASE_NONE,
            NULL, 0x0, "Address of the node reported unreachable", HFILL } },
        { &hf_hyperdht_down_hint_node_ipv4,
          { "IPv4 Address", "hyperdht.down_hint.node.ipv4", FT_IPv4, BASE_NONE,
            NULL, 0x0, NULL, HFILL } },
        { &hf_hyperdht_down_hint_node_port,
          { "Port", "hyperdht.down_hint.node.port", FT_UINT16, BASE_DEC,
            NULL, 0x0, NULL, HFILL } },
        { &hf_hyperdht_delayed_ping_ms,
          { "Delay", "hyperdht.delayed_ping.delay", FT_UINT32, BASE_DEC | BASE_UNIT_STRING,
            UNS(&units_milliseconds), 0x0, "Delay before the reply is sent", HFILL } },

        { &hf_hyperdht_handshake_flags,
          { "Handshake Flags", "hyperdht.peer_handshake.flags", FT_UINT8, BASE_HEX,
            NULL, 0x0, NULL, HFILL } },
        { &hf_hyperdht_handshake_flag_peer,
          { "Peer Address", "hyperdht.peer_handshake.flag.peer", FT_BOOLEAN, 8,
            NULL, HYPERDHT_HANDSHAKE_FLAG_PEER, NULL, HFILL } },
        { &hf_hyperdht_handshake_flag_relay,
          { "Relay Address", "hyperdht.peer_handshake.flag.relay", FT_BOOLEAN, 8,
            NULL, HYPERDHT_HANDSHAKE_FLAG_RELAY, NULL, HFILL } },
        { &hf_hyperdht_handshake_mode,
          { "Handshake Mode", "hyperdht.peer_handshake.mode", FT_UINT8, BASE_DEC,
            VALS(holepunch_mode_names), 0x0, NULL, HFILL } },
        { &hf_hyperdht_handshake_noise,
          { "Noise Payload", "hyperdht.peer_handshake.noise", FT_BYTES, BASE_NONE,
            NULL, 0x0, "Encrypted handshake payload", HFILL } },
        { &hf_hyperdht_handshake_peer,
          { "Peer Address", "hyperdht.peer_handshake.peer", FT_BYTES, BASE_NONE,
            NULL, 0x0, NULL, HFILL } },
        { &hf_hyperdht_handshake_peer_ipv4,
          { "IPv4 Address", "hyperdht.peer_handshake.peer.ipv4", FT_IPv4, BASE_NONE,
            NULL, 0x0, NULL, HFILL } },
        { &hf_hyperdht_handshake_peer_port,
          { "Port", "hyperdht.peer_handshake.peer.port", FT_UINT16, BASE_DEC,
            NULL, 0x0, NULL, HFILL } },
        { &hf_hyperdht_handshake_relay,
          { "Relay Address", "hyperdht.peer_handshake.relay", FT_BYTES, BASE_NONE,
            NULL, 0x0, NULL, HFILL } },
        { &hf_hyperdht_handshake_relay_ipv4,
          { "IPv4 Address", "hyperdht.peer_handshake.relay.ipv4", FT_IPv4, BASE_NONE,
            NULL, 0x0, NULL, HFILL } },
        { &hf_hyperdht_handshake_relay_port,
          { "Port", "hyperdht.peer_handshake.relay.port", FT_UINT16, BASE_DEC,
            NULL, 0x0, NULL, HFILL } },
        { &hf_hyperdht_holepunch_flags,
          { "Holepunch Flags", "hyperdht.peer_holepunch.flags", FT_UINT8, BASE_HEX,
            NULL, 0x0, NULL, HFILL } },
        { &hf_hyperdht_holepunch_flag_peer,
          { "Peer Address", "hyperdht.peer_holepunch.flag.peer", FT_BOOLEAN, 8,
            NULL, HYPERDHT_HOLEPUNCH_FLAG_PEER, NULL, HFILL } },
        { &hf_hyperdht_holepunch_mode,
          { "Holepunch Mode", "hyperdht.peer_holepunch.mode", FT_UINT8, BASE_DEC,
            VALS(holepunch_mode_names), 0x0, NULL, HFILL } },
        { &hf_hyperdht_holepunch_id,
          { "Holepunch ID", "hyperdht.peer_holepunch.id", FT_UINT64, BASE_DEC,
            NULL, 0x0, NULL, HFILL } },
        { &hf_hyperdht_holepunch_payload,
          { "Holepunch Payload", "hyperdht.peer_holepunch.payload", FT_BYTES, BASE_NONE,
            NULL, 0x0, "Encrypted holepunch payload", HFILL } },
        { &hf_hyperdht_holepunch_peer,
          { "Peer Address", "hyperdht.peer_holepunch.peer", FT_BYTES, BASE_NONE,
            NULL, 0x0, NULL, HFILL } },
        { &hf_hyperdht_holepunch_peer_ipv4,
          { "IPv4 Address", "hyperdht.peer_holepunch.peer.ipv4", FT_IPv4, BASE_NONE,
            NULL, 0x0, NULL, HFILL } },
        { &hf_hyperdht_holepunch_peer_port,
          { "Port", "hyperdht.peer_holepunch.peer.port", FT_UINT16, BASE_DEC,
            NULL, 0x0, NULL, HFILL } },

        { &hf_hyperdht_announce_flags,
          { "Announce Flags", "hyperdht.announce.flags", FT_UINT8, BASE_HEX,
            NULL, 0x0, NULL, HFILL } },
        { &hf_hyperdht_announce_flag_peer,
          { "Peer", "hyperdht.announce.flag.peer", FT_BOOLEAN, 8,
            NULL, HYPERDHT_ANNOUNCE_FLAG_PEER, NULL, HFILL } },
        { &hf_hyperdht_announce_flag_refresh,
          { "Refresh", "hyperdht.announce.flag.refresh", FT_BOOLEAN, 8,
            NULL, HYPERDHT_ANNOUNCE_FLAG_REFRESH, NULL, HFILL } },
        { &hf_hyperdht_announce_flag_signature,
          { "Signature", "hyperdht.announce.flag.signature", FT_BOOLEAN, 8,
            NULL, HYPERDHT_ANNOUNCE_FLAG_SIGNATURE, NULL, HFILL } },
        { &hf_hyperdht_announce_flag_bump,
          { "Bump", "hyperdht.announce.flag.bump", FT_BOOLEAN, 8,
            NULL, HYPERDHT_ANNOUNCE_FLAG_BUMP, NULL, HFILL } },
        { &hf_hyperdht_announce_peer,
          { "Peer Public Key", "hyperdht.announce.peer", FT_BYTES, BASE_NONE,
            NULL, 0x0, NULL, HFILL } },
        { &hf_hyperdht_announce_peer_relay,
          { "Peer Relay", "hyperdht.announce.peer.relay", FT_BYTES, BASE_NONE,
            NULL, 0x0, NULL, HFILL } },
        { &hf_hyperdht_announce_peer_relay_ipv4,
          { "IPv4 Address", "hyperdht.announce.peer.relay.ipv4", FT_IPv4, BASE_NONE,
            NULL, 0x0, NULL, HFILL } },
        { &hf_hyperdht_announce_peer_relay_port,
          { "Port", "hyperdht.announce.peer.relay.port", FT_UINT16, BASE_DEC,
            NULL, 0x0, NULL, HFILL } },
        { &hf_hyperdht_announce_refresh,
          { "Refresh", "hyperdht.announce.refresh", FT_BYTES, BASE_NONE,
            NULL, 0x0, NULL, HFILL } },
        { &hf_hyperdht_announce_signature,
          { "Signature", "hyperdht.announce.signature", FT_BYTES, BASE_NONE,
            NULL, 0x0, NULL, HFILL } },
        { &hf_hyperdht_announce_bump,
          { "Bump", "hyperdht.announce.bump", FT_UINT64, BASE_DEC,
            NULL, 0x0, NULL, HFILL } },

        { &hf_hyperdht_mutable_put_public_key,
          { "Public Key", "hyperdht.mutable_put.public_key", FT_BYTES, BASE_NONE,
            NULL, 0x0, NULL, HFILL } },
        { &hf_hyperdht_mutable_put_seq,
          { "Sequence", "hyperdht.mutable_put.seq", FT_UINT64, BASE_DEC,
            NULL, 0x0, NULL, HFILL } },
        { &hf_hyperdht_mutable_put_value,
          { "Value", "hyperdht.mutable_put.value", FT_BYTES, BASE_NONE,
            NULL, 0x0, NULL, HFILL } },
        { &hf_hyperdht_mutable_put_signature,
          { "Signature", "hyperdht.mutable_put.signature", FT_BYTES, BASE_NONE,
            NULL, 0x0, NULL, HFILL } },
        { &hf_hyperdht_mutable_get_req_seq,
          { "Sequence", "hyperdht.mutable_get.seq", FT_UINT64, BASE_DEC,
            NULL, 0x0, "Sequence number the requester already holds", HFILL } },
        { &hf_hyperdht_mutable_get_resp_seq,
          { "Sequence", "hyperdht.mutable_get.response.seq", FT_UINT64, BASE_DEC,
            NULL, 0x0, NULL, HFILL } },
        { &hf_hyperdht_mutable_get_resp_value,
          { "Value", "hyperdht.mutable_get.response.value", FT_BYTES, BASE_NONE,
            NULL, 0x0, NULL, HFILL } },
        { &hf_hyperdht_mutable_get_resp_signature,
          { "Signature", "hyperdht.mutable_get.response.signature", FT_BYTES, BASE_NONE,
            NULL, 0x0, NULL, HFILL } },
        { &hf_hyperdht_immutable_value,
          { "Immutable Value", "hyperdht.immutable.value", FT_BYTES, BASE_NONE,
            NULL, 0x0, NULL, HFILL } },

        { &hf_hyperdht_plugin_name,
          { "Plugin Name", "hyperdht.plugin.name", FT_STRING, BASE_NONE,
            NULL, 0x0, NULL, HFILL } },
        { &hf_hyperdht_plugin_version,
          { "Plugin Version", "hyperdht.plugin.version", FT_UINT64, BASE_DEC,
            NULL, 0x0, "Request is dropped unless it matches the registered plugin", HFILL } },
        { &hf_hyperdht_plugin_command,
          { "Plugin Command", "hyperdht.plugin.command", FT_UINT64, BASE_DEC,
            NULL, 0x0, "Command defined by the plugin, not by HyperDHT", HFILL } },
        { &hf_hyperdht_plugin_flags,
          { "Plugin Flags", "hyperdht.plugin.flags", FT_UINT8, BASE_HEX,
            NULL, 0x0, NULL, HFILL } },
        { &hf_hyperdht_plugin_flag_value,
          { "Value", "hyperdht.plugin.flag.value", FT_BOOLEAN, 8,
            NULL, HYPERDHT_PLUGIN_FLAG_VALUE, NULL, HFILL } },
        { &hf_hyperdht_plugin_value,
          { "Plugin Value", "hyperdht.plugin.value", FT_BYTES, BASE_NONE,
            NULL, 0x0, "Plugin-defined request payload", HFILL } },
        { &hf_hyperdht_plugin_resp_value,
          { "Plugin Value", "hyperdht.plugin.response.value", FT_BYTES, BASE_NONE,
            NULL, 0x0, "Plugin-defined response payload", HFILL } },

        { &hf_hyperdht_lookup_peer_count,
          { "Peer Count", "hyperdht.lookup.peer_count", FT_UINT64, BASE_DEC,
            NULL, 0x0, NULL, HFILL } },
        { &hf_hyperdht_lookup_peer,
          { "Peer Public Key", "hyperdht.lookup.peer", FT_BYTES, BASE_NONE,
            NULL, 0x0, NULL, HFILL } },
        { &hf_hyperdht_lookup_peer_relay,
          { "Peer Relay", "hyperdht.lookup.peer.relay", FT_BYTES, BASE_NONE,
            NULL, 0x0, NULL, HFILL } },
        { &hf_hyperdht_lookup_peer_relay_ipv4,
          { "IPv4 Address", "hyperdht.lookup.peer.relay.ipv4", FT_IPv4, BASE_NONE,
            NULL, 0x0, NULL, HFILL } },
        { &hf_hyperdht_lookup_peer_relay_port,
          { "Port", "hyperdht.lookup.peer.relay.port", FT_UINT16, BASE_DEC,
            NULL, 0x0, NULL, HFILL } },
        { &hf_hyperdht_lookup_bump,
          { "Bump", "hyperdht.lookup.bump", FT_UINT64, BASE_DEC,
            NULL, 0x0, NULL, HFILL } },
        { &hf_hyperdht_find_peer_peer,
          { "Peer Public Key", "hyperdht.find_peer.peer", FT_BYTES, BASE_NONE,
            NULL, 0x0, NULL, HFILL } },
        { &hf_hyperdht_find_peer_peer_relay,
          { "Peer Relay", "hyperdht.find_peer.peer.relay", FT_BYTES, BASE_NONE,
            NULL, 0x0, NULL, HFILL } },
        { &hf_hyperdht_find_peer_peer_relay_ipv4,
          { "IPv4 Address", "hyperdht.find_peer.peer.relay.ipv4", FT_IPv4, BASE_NONE,
            NULL, 0x0, NULL, HFILL } },
        { &hf_hyperdht_find_peer_peer_relay_port,
          { "Port", "hyperdht.find_peer.peer.relay.port", FT_UINT16, BASE_DEC,
            NULL, 0x0, NULL, HFILL } },

        { &hf_hyperdht_request_in,
          { "Request In", "hyperdht.request_in", FT_FRAMENUM, BASE_NONE,
            FRAMENUM_TYPE(FT_FRAMENUM_REQUEST), 0x0,
            "This is a response to the DHT request in this frame", HFILL } },
        { &hf_hyperdht_response_in,
          { "Response In", "hyperdht.response_in", FT_FRAMENUM, BASE_NONE,
            FRAMENUM_TYPE(FT_FRAMENUM_RESPONSE), 0x0,
            "The response to this DHT request is in this frame", HFILL } },
        { &hf_hyperdht_response_time,
          { "Response Time", "hyperdht.response_time", FT_RELATIVE_TIME, BASE_NONE,
            NULL, 0x0, "Time between the DHT request and this response", HFILL } },
        { &hf_hyperdht_trailing,
          { "Trailing Data", "hyperdht.trailing", FT_BYTES, BASE_NONE,
            NULL, 0x0, "Undecoded data after the end of the message", HFILL } },
    };

    static int *ett[] = {
        &ett_hyperdht,
        &ett_hyperdht_flags,
        &ett_hyperdht_addr,
        &ett_hyperdht_value,
        &ett_hyperdht_handshake_flags,
        &ett_hyperdht_holepunch_flags,
        &ett_hyperdht_announce_flags,
        &ett_hyperdht_closer_nodes,
        &ett_hyperdht_peer_record,
        &ett_hyperdht_plugin_flags,
    };

    static ei_register_info ei[] = {
        { &ei_hyperdht_unknown_command,
          { "hyperdht.unknown_command", PI_UNDECODED, PI_WARN,
            "Unrecognized command", EXPFILL } },
        { &ei_hyperdht_unknown_error,
          { "hyperdht.unknown_error", PI_UNDECODED, PI_WARN,
            "Unrecognized error code", EXPFILL } },
        { &ei_hyperdht_trailing_bytes,
          { "hyperdht.trailing_bytes", PI_UNDECODED, PI_WARN,
            "Trailing data after end of message", EXPFILL } },
        { &ei_hyperdht_response_missing,
          { "hyperdht.response_missing", PI_SEQUENCE, PI_NOTE,
            "No response captured for this request", EXPFILL } },
        { &ei_hyperdht_request_missing,
          { "hyperdht.request_missing", PI_SEQUENCE, PI_NOTE,
            "No request captured for this response", EXPFILL } },
        { &ei_hyperdht_bad_length,
          { "hyperdht.bad_length", PI_MALFORMED, PI_ERROR,
            "Length or element count exceeds the remaining packet data", EXPFILL } },
    };

    proto_hyperdht = proto_register_protocol("HyperDHT / DHT-RPC", "HyperDHT", "hyperdht");

    proto_register_field_array(proto_hyperdht, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    expert_hyperdht = expert_register_protocol(proto_hyperdht);
    expert_register_field_array(expert_hyperdht, ei, array_length(ei));

    hyperdht_handle = register_dissector("hyperdht", dissect_hyperdht, proto_hyperdht);
}

void
proto_reg_handoff_hyperdht(void)
{
    dissector_add_uint_range_with_preference("udp.port", HYPERDHT_UDP_PORTS, hyperdht_handle);

    /* Enabled by default: the test accepts only a fully decoded message with
     * a known command or error, a plausible unicast address, and an exact
     * length match. */
    heur_dissector_add("udp", dissect_hyperdht_heur, "HyperDHT over UDP",
                       "hyperdht_udp", proto_hyperdht, HEURISTIC_ENABLE);
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
