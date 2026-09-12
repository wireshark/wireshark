/* packet-moq-lite.c
 * Routines for Media over QUIC Lite (moq-lite) dissection
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/*
 * moq-lite is a stripped down variant of Media over QUIC Transport designed to
 * fanout live media 1->N, using QUIC streams for prioritization.
 *
 * This dissector implements draft-lcurley-moq-lite-05:
 * https://datatracker.ietf.org/doc/draft-lcurley-moq-lite/
 *
 * Over bare QUIC the protocol is negotiated with the ALPN token "moq-lite-xx",
 * which is how this dissector is reached. A session running over WebTransport
 * keeps the "h3" ALPN and advertises moq-lite in the WT-Protocol header, which
 * Wireshark does not currently use to select a subprotocol dissector.
 *
 * Draft 02 and earlier negotiated the version with a SESSION_CLIENT and
 * SESSION_SERVER message on a Session stream instead of relying on the ALPN
 * token alone. Those messages are dissected as well, and the version they
 * carry selects the layouts that changed since: the Session stream itself, the
 * subscriber properties of SUBSCRIBE, and the timestamp of a FRAME. Drafts 03
 * and 04 are dissected with the draft 05 layouts, which they mostly share.
 *
 * A session consists of:
 *  - one bidirectional stream per transaction (announce, subscribe, fetch,
 *    probe, goaway, track), each starting with a stream type varint written by
 *    the endpoint that opened the stream,
 *  - unidirectional streams carrying setup parameters and group data,
 *  - optionally QUIC datagrams carrying single frame groups.
 *
 * Which message is being parsed is therefore a function of the stream type,
 * the direction (opener or peer) and the position within the stream, rather
 * than of an explicit type on the wire. The exception is the publisher side of
 * a Subscribe stream, where SUBSCRIBE_OK/END/DROP do carry a type varint.
 */

#include "config.h"

#include <epan/packet.h>
#include <epan/exceptions.h>
#include <epan/conversation.h>
#include <epan/expert.h>
#include <epan/prefs.h>
#include <epan/proto_data.h>
#include <epan/unit_strings.h>
#include <wsutil/array.h>
#include <wsutil/str_util.h>

#include "packet-quic.h"
#include "packet-tls.h"

void proto_register_moq_lite(void);
void proto_reg_handoff_moq_lite(void);

/* Bidirectional stream types (draft-05, Section 5.1). */
#define MOQL_BIDI_STREAM_SESSION    0x0     /* moq-lite-02 and earlier. */
#define MOQL_BIDI_STREAM_ANNOUNCE   0x1
#define MOQL_BIDI_STREAM_SUBSCRIBE  0x2
#define MOQL_BIDI_STREAM_FETCH      0x3
#define MOQL_BIDI_STREAM_PROBE      0x4
#define MOQL_BIDI_STREAM_GOAWAY     0x5
#define MOQL_BIDI_STREAM_TRACK      0x6

/* Unidirectional stream types (draft-05, Section 6.3). */
#define MOQL_UNI_STREAM_GROUP       0x0
#define MOQL_UNI_STREAM_SETUP       0x1

/* Message types on the publisher side of a Subscribe stream. */
#define MOQL_SUBSCRIBE_OK           0x0
#define MOQL_SUBSCRIBE_END          0x1
#define MOQL_SUBSCRIBE_DROP         0x2

/* Setup parameters (draft-05, Section 7.3). */
#define MOQL_SETUP_PARAM_PROBE      0x1
#define MOQL_SETUP_PARAM_PATH       0x2

/* Sentinel for a stream whose leading stream type was not captured. */
#define MOQL_STREAM_TYPE_UNKNOWN    UINT64_MAX

/* Maximum size of a datagram body (draft-05, Section 6.5). */
#define MOQL_MAX_DATAGRAM_SIZE      1200

/*
 * Version constants, as carried by SESSION_CLIENT and SESSION_SERVER in
 * moq-lite-02 and earlier. The low byte is the draft number.
 */
#define MOQL_VERSION_BASE           UINT64_C(0xff0dad00)
#define MOQL_VERSION_MASK           UINT64_C(0xffffff00)

/* The draft implemented here, assumed for sessions of an unknown version. */
#define MOQL_VERSION_LATEST         5

/*
 * The last draft with a Session stream; up to and including this version the
 * layout of several messages differs from the current draft.
 */
#define MOQL_VERSION_LEGACY_MAX     2

/* Number of messages described in the info column, per stream and packet. */
#define MOQL_MAX_COL_INFO_MESSAGES  4

static int proto_moq_lite;

static int hf_moql_stream_type;
static int hf_moql_message;
static int hf_moql_message_type;
static int hf_moql_message_length;
static int hf_moql_string_length;
static int hf_moql_setup_parameter_count;
static int hf_moql_setup_parameter;
static int hf_moql_setup_parameter_id;
static int hf_moql_setup_parameter_length;
static int hf_moql_setup_parameter_value;
static int hf_moql_setup_probe_level;
static int hf_moql_session_parameter;
static int hf_moql_session_parameter_count;
static int hf_moql_session_parameter_id;
static int hf_moql_session_parameter_length;
static int hf_moql_session_parameter_value;
static int hf_moql_version;
static int hf_moql_version_count;
static int hf_moql_session_bitrate;
static int hf_moql_message_body;
static int hf_moql_setup_path;
static int hf_moql_broadcast_path;
static int hf_moql_broadcast_path_prefix;
static int hf_moql_broadcast_path_suffix;
static int hf_moql_exclude_hop;
static int hf_moql_hop_id;
static int hf_moql_hop_count;
static int hf_moql_active_count;
static int hf_moql_announce_status;
static int hf_moql_track_name;
static int hf_moql_subscribe_id;
static int hf_moql_subscriber_priority;
static int hf_moql_subscriber_ordered;
static int hf_moql_subscriber_max_latency;
static int hf_moql_group_start;
static int hf_moql_group_end;
static int hf_moql_publisher_priority;
static int hf_moql_publisher_ordered;
static int hf_moql_publisher_max_latency;
static int hf_moql_timescale;
static int hf_moql_subscribe_type;
static int hf_moql_group;
static int hf_moql_drop_group_start;
static int hf_moql_drop_group_end;
static int hf_moql_error_code;
static int hf_moql_group_sequence;
static int hf_moql_probe_bitrate;
static int hf_moql_probe_rtt;
static int hf_moql_goaway_uri;
static int hf_moql_frame_timestamp_delta;
static int hf_moql_frame_timestamp;
static int hf_moql_frame_time;
static int hf_moql_frame_payload;
static int hf_moql_datagram_timestamp;
static int hf_moql_subscribe_frame;
static int hf_moql_track_info_frame;

static int ett_moql;
static int ett_moql_message;
static int ett_moql_setup_parameter;
static int ett_moql_session_parameter;

static expert_field ei_moql_unknown_stream_type;
static expert_field ei_moql_unknown_version;
static expert_field ei_moql_stream_type_missing;
static expert_field ei_moql_unexpected_message;
static expert_field ei_moql_incomplete_message;
static expert_field ei_moql_extra_data;
static expert_field ei_moql_protocol_violation;

static dissector_handle_t moql_handle;
static dissector_handle_t moql_datagram_handle;

/* Reassemble messages that span multiple QUIC STREAM frames. */
static bool moql_desegment = true;

static const value_string moql_bidi_stream_type_vals[] = {
    { MOQL_BIDI_STREAM_SESSION,   "Session" },
    { MOQL_BIDI_STREAM_ANNOUNCE,  "Announce" },
    { MOQL_BIDI_STREAM_SUBSCRIBE, "Subscribe" },
    { MOQL_BIDI_STREAM_FETCH,     "Fetch" },
    { MOQL_BIDI_STREAM_PROBE,     "Probe" },
    { MOQL_BIDI_STREAM_GOAWAY,    "Goaway" },
    { MOQL_BIDI_STREAM_TRACK,     "Track" },
    { 0, NULL }
};

static const value_string moql_uni_stream_type_vals[] = {
    { MOQL_UNI_STREAM_GROUP, "Group" },
    { MOQL_UNI_STREAM_SETUP, "Setup" },
    { 0, NULL }
};

static const val64_string moql_subscribe_type_vals[] = {
    { MOQL_SUBSCRIBE_OK,   "SUBSCRIBE_OK" },
    { MOQL_SUBSCRIBE_END,  "SUBSCRIBE_END" },
    { MOQL_SUBSCRIBE_DROP, "SUBSCRIBE_DROP" },
    { 0, NULL }
};

static const val64_string moql_setup_parameter_vals[] = {
    { MOQL_SETUP_PARAM_PROBE, "Probe" },
    { MOQL_SETUP_PARAM_PATH,  "Path" },
    { 0, NULL }
};

static const val64_string moql_probe_level_vals[] = {
    { 0, "None" },
    { 1, "Report" },
    { 2, "Increase" },
    { 0, NULL }
};

static const val64_string moql_announce_status_vals[] = {
    { 0, "ended" },
    { 1, "active" },
    { 0, NULL }
};

static const val64_string moql_version_vals[] = {
    { MOQL_VERSION_BASE + 0, "moq-lite-00" },
    { MOQL_VERSION_BASE + 1, "moq-lite-01" },
    { MOQL_VERSION_BASE + 2, "moq-lite-02" },
    { MOQL_VERSION_BASE + 3, "moq-lite-03" },
    { MOQL_VERSION_BASE + 4, "moq-lite-04" },
    { MOQL_VERSION_BASE + 5, "moq-lite-05" },
    { 0, NULL }
};

static const value_string moql_ordered_vals[] = {
    { 0, "Descending (newest group first)" },
    { 1, "Ascending (oldest group first)" },
    { 0, NULL }
};

/*
 * Message kinds, used internally and as the value of the generated
 * moql.message_type field. These are not wire values: moq-lite identifies most
 * messages by stream type and position instead.
 */
typedef enum {
    MOQL_MSG_NONE = 0,
    MOQL_MSG_SETUP,
    MOQL_MSG_SESSION_CLIENT,
    MOQL_MSG_SESSION_SERVER,
    MOQL_MSG_SESSION_UPDATE,
    MOQL_MSG_ANNOUNCE_PLEASE,
    MOQL_MSG_ANNOUNCE_INIT,
    MOQL_MSG_ANNOUNCE,
    MOQL_MSG_ANNOUNCE_REQUEST,
    MOQL_MSG_ANNOUNCE_OK,
    MOQL_MSG_ANNOUNCE_BROADCAST,
    MOQL_MSG_SUBSCRIBE,
    MOQL_MSG_SUBSCRIBE_UPDATE,
    MOQL_MSG_SUBSCRIBE_RESPONSE,    /* Resolved to _OK/_END/_DROP on the wire. */
    MOQL_MSG_SUBSCRIBE_OK,
    MOQL_MSG_SUBSCRIBE_END,
    MOQL_MSG_SUBSCRIBE_DROP,
    MOQL_MSG_TRACK,
    MOQL_MSG_TRACK_INFO,
    MOQL_MSG_FETCH,
    MOQL_MSG_PROBE,
    MOQL_MSG_GOAWAY,
    MOQL_MSG_GROUP,
    MOQL_MSG_FRAME,
} moql_message_type_t;

static const value_string moql_message_type_vals[] = {
    { MOQL_MSG_SETUP,              "SETUP" },
    { MOQL_MSG_SESSION_CLIENT,     "SESSION_CLIENT" },
    { MOQL_MSG_SESSION_SERVER,     "SESSION_SERVER" },
    { MOQL_MSG_SESSION_UPDATE,     "SESSION_UPDATE" },
    { MOQL_MSG_ANNOUNCE_PLEASE,    "ANNOUNCE_PLEASE" },
    { MOQL_MSG_ANNOUNCE_INIT,      "ANNOUNCE_INIT" },
    { MOQL_MSG_ANNOUNCE,           "ANNOUNCE" },
    { MOQL_MSG_ANNOUNCE_REQUEST,   "ANNOUNCE_REQUEST" },
    { MOQL_MSG_ANNOUNCE_OK,        "ANNOUNCE_OK" },
    { MOQL_MSG_ANNOUNCE_BROADCAST, "ANNOUNCE_BROADCAST" },
    { MOQL_MSG_SUBSCRIBE,          "SUBSCRIBE" },
    { MOQL_MSG_SUBSCRIBE_UPDATE,   "SUBSCRIBE_UPDATE" },
    { MOQL_MSG_SUBSCRIBE_OK,       "SUBSCRIBE_OK" },
    { MOQL_MSG_SUBSCRIBE_END,      "SUBSCRIBE_END" },
    { MOQL_MSG_SUBSCRIBE_DROP,     "SUBSCRIBE_DROP" },
    { MOQL_MSG_TRACK,              "TRACK" },
    { MOQL_MSG_TRACK_INFO,         "TRACK_INFO" },
    { MOQL_MSG_FETCH,              "FETCH" },
    { MOQL_MSG_PROBE,              "PROBE" },
    { MOQL_MSG_GOAWAY,             "GOAWAY" },
    { MOQL_MSG_GROUP,              "GROUP" },
    { MOQL_MSG_FRAME,              "FRAME" },
    { 0, NULL }
};

/* Immutable publisher properties of a track, learned from TRACK_INFO. */
typedef struct _moql_track {
    uint32_t    frame_num;      /* Frame containing the TRACK_INFO. */
    uint64_t    timescale;
} moql_track_t;

/* A subscription, learned from SUBSCRIBE. */
typedef struct _moql_subscription {
    uint32_t    frame_num;      /* Frame containing the SUBSCRIBE. */
    const char *broadcast_path;
    const char *track_name;
} moql_subscription_t;

/* Session (i.e. QUIC connection) wide state. */
typedef struct _moql_session {
    wmem_map_t *subscriptions;  /* Subscribe ID -> moql_subscription_t */
    wmem_map_t *tracks;         /* Broadcast path and track name -> moql_track_t */
    unsigned    version;        /* Draft number, MOQL_VERSION_LATEST if unknown. */
    bool        version_known;
} moql_session_t;

typedef struct {
    int64_t value;
    bool overflow;
} moql_timestamp_t;

/*
 * Per stream state. Both directions of a bidirectional stream share a single
 * instance, keyed on the direction of the endpoint that opened the stream.
 */
typedef struct _moql_stream {
    uint64_t    stream_type;
    uint64_t    data_start;     /* Stream offset after the stream type varint. */
    /*
     * Stream offset at which the messages following the leading message of a
     * direction start, indexed by direction (0: opener, 1: peer).
     */
    uint64_t    body_offset[2];
    bool        body_offset_known[2];
    const char *broadcast_path; /* Fetch and Track streams. */
    const char *track_name;
    moql_subscription_t *subscription;  /* Group streams. */
    /*
     * Absolute frame timestamps, keyed by the stream offset of the FRAME.
     * FRAME timestamps are deltas, so the running sum is computed on the first
     * pass and cached, which keeps random access dissection consistent.
     */
    wmem_map_t *frame_timestamps;
    moql_timestamp_t timestamp; /* Running sum, first pass only. */
} moql_stream_t;

static moql_session_t *
moql_session_lookup_or_create(packet_info *pinfo)
{
    conversation_t *conversation = find_or_create_conversation(pinfo);
    moql_session_t *session;

    session = (moql_session_t *)conversation_get_proto_data(conversation, proto_moq_lite);
    if (session == NULL) {
        session = wmem_new0(wmem_file_scope(), moql_session_t);
        session->subscriptions = wmem_map_new(wmem_file_scope(), g_int64_hash, g_int64_equal);
        session->tracks = wmem_map_new(wmem_file_scope(), wmem_str_hash, g_str_equal);
        session->version = MOQL_VERSION_LATEST;
        const char *alpn = tls_get_alpn(tls_get_current_session(pinfo));
        if (alpn != NULL && strlen(alpn) == 11 &&
            strncmp(alpn, "moq-lite-0", 10) == 0 && alpn[10] >= '0' && alpn[10] <= '5') {
            session->version = (unsigned)(alpn[10] - '0');
        }
        conversation_add_proto_data(conversation, proto_moq_lite, session);
    }

    return session;
}

static moql_track_t *
moql_track_lookup(moql_session_t *session, packet_info *pinfo,
                  const char *broadcast_path, const char *track_name)
{
    if (session == NULL || broadcast_path == NULL || track_name == NULL) {
        return NULL;
    }

    char *key = wmem_strdup_printf(pinfo->pool, "%zu:%s%s", strlen(broadcast_path), broadcast_path, track_name);

    return (moql_track_t *)wmem_map_lookup(session->tracks, key);
}

/*
 * Try to read a QUIC variable length integer, returning false (without
 * throwing) if the buffer does not hold the whole varint.
 */
static bool
moql_try_get_varint(tvbuff_t *tvb, int offset, uint64_t *value, uint32_t *lenvar)
{
    if (tvb_reported_length_remaining(tvb, offset) < 1) {
        return false;
    }

    unsigned len = 1U << (tvb_get_uint8(tvb, offset) >> 6);
    if (tvb_reported_length_remaining(tvb, offset) < len) {
        return false;
    }

    *lenvar = len;
    if (value != NULL) {
        unsigned decoded = tvb_get_varint(tvb, offset, len, value, ENC_VARINT_QUIC);
        DISSECTOR_ASSERT(decoded == len);
    }

    return true;
}

/* Add a QUIC varint and return its encoded length. */
static unsigned
moql_add_varint(tvbuff_t *tvb, proto_tree *tree, int offset, int hf, uint64_t *value)
{
    unsigned length;

    proto_tree_add_item_ret_varint(tree, hf, tvb, offset, -1,
                                  ENC_VARINT_QUIC, value, &length);
    return length;
}

/*
 * Add a varint length prefixed UTF-8 string, returning the number of bytes
 * consumed. Escaped metadata is returned in *retval, allocated from packet scope.
 */
static int
moql_add_string(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset,
                int hf_string, const char **retval)
{
    uint64_t str_len;
    uint32_t lenvar;

    lenvar = moql_add_varint(tvb, tree, offset, hf_moql_string_length, &str_len);
    offset += lenvar;

    if (str_len > INT32_MAX) {
        THROW(ReportedBoundsError);
    }

    proto_tree_add_item(tree, hf_string, tvb, offset, (int)str_len, ENC_UTF_8);
    if (retval != NULL) {
        /* Keep metadata unbounded and reversible, including NUL and backslash. */
        *retval = tvb_format_text(pinfo->pool, tvb, offset, (int)str_len);
    }

    return lenvar + (int)str_len;
}

/* Decode a zigzag mapped value (draft-05, Section 7.16). */
static int64_t
moql_zigzag_decode(uint64_t value)
{
    return (int64_t)(value >> 1) ^ -(int64_t)(value & 1);
}

/*
 * Determine the message expected on a bidirectional stream. "leading" is true
 * for the first message sent in the given direction.
 */
static moql_message_type_t
moql_expected_bidi_message(uint64_t stream_type, bool from_opener, bool leading, bool legacy)
{
    switch (stream_type) {
    case MOQL_BIDI_STREAM_SESSION:
        /* Only moq-lite-02 and earlier have a Session stream. */
        if (leading) {
            return from_opener ? MOQL_MSG_SESSION_CLIENT : MOQL_MSG_SESSION_SERVER;
        }
        return MOQL_MSG_SESSION_UPDATE;

    case MOQL_BIDI_STREAM_ANNOUNCE:
        if (from_opener) {
            if (!leading) {
                return MOQL_MSG_NONE;
            }
            return legacy ? MOQL_MSG_ANNOUNCE_PLEASE : MOQL_MSG_ANNOUNCE_REQUEST;
        }
        if (legacy) {
            return leading ? MOQL_MSG_ANNOUNCE_INIT : MOQL_MSG_ANNOUNCE;
        }
        return leading ? MOQL_MSG_ANNOUNCE_OK : MOQL_MSG_ANNOUNCE_BROADCAST;

    case MOQL_BIDI_STREAM_SUBSCRIBE:
        if (from_opener) {
            return leading ? MOQL_MSG_SUBSCRIBE : MOQL_MSG_SUBSCRIBE_UPDATE;
        }
        /* The publisher's responses only carry a type varint since draft 03. */
        return legacy ? MOQL_MSG_SUBSCRIBE_OK : MOQL_MSG_SUBSCRIBE_RESPONSE;

    case MOQL_BIDI_STREAM_FETCH:
        if (from_opener) {
            return leading ? MOQL_MSG_FETCH : MOQL_MSG_NONE;
        }
        return MOQL_MSG_FRAME;

    case MOQL_BIDI_STREAM_PROBE:
        return MOQL_MSG_PROBE;

    case MOQL_BIDI_STREAM_GOAWAY:
        if (from_opener) {
            return leading ? MOQL_MSG_GOAWAY : MOQL_MSG_NONE;
        }
        return MOQL_MSG_NONE;

    case MOQL_BIDI_STREAM_TRACK:
        if (from_opener) {
            return leading ? MOQL_MSG_TRACK : MOQL_MSG_NONE;
        }
        return leading ? MOQL_MSG_TRACK_INFO : MOQL_MSG_NONE;

    default:
        return MOQL_MSG_NONE;
    }
}

/*
 * Determine the message expected on a unidirectional stream. Only the endpoint
 * that opened the stream ever sends data on it.
 */
static moql_message_type_t
moql_expected_uni_message(uint64_t stream_type, bool leading, bool legacy)
{
    switch (stream_type) {
    case MOQL_UNI_STREAM_GROUP:
        return leading ? MOQL_MSG_GROUP : MOQL_MSG_FRAME;

    case MOQL_UNI_STREAM_SETUP:
        /* The Setup stream was added in draft 05. */
        if (legacy) {
            return MOQL_MSG_NONE;
        }
        return leading ? MOQL_MSG_SETUP : MOQL_MSG_NONE;

    default:
        return MOQL_MSG_NONE;
    }
}

/*
 * Dissect a parameter list: a count followed by that many {ID, length, value}
 * triples. Both the SETUP message and the legacy session messages use it, with
 * their own parameter registries.
 */
static int
moql_dissect_parameters(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset,
                        uint64_t param_count, bool setup)
{
    int start = offset;

    for (uint64_t i = 0; i < param_count; i++) {
        proto_item *param_ti;
        proto_tree *param_tree;
        uint64_t    param_id, param_len;
        uint32_t    lenvar;
        int         param_start = offset;

        param_ti = proto_tree_add_item(tree,
                                       setup ? hf_moql_setup_parameter : hf_moql_session_parameter,
                                       tvb, offset, -1, ENC_NA);
        param_tree = proto_item_add_subtree(param_ti, setup ? ett_moql_setup_parameter
                                                            : ett_moql_session_parameter);

        proto_tree_add_item_ret_varint(param_tree,
                                       setup ? hf_moql_setup_parameter_id
                                             : hf_moql_session_parameter_id,
                                       tvb, offset, -1, ENC_VARINT_QUIC, &param_id, &lenvar);
        offset += lenvar;
        proto_tree_add_item_ret_varint(param_tree,
                                       setup ? hf_moql_setup_parameter_length
                                             : hf_moql_session_parameter_length,
                                       tvb, offset, -1, ENC_VARINT_QUIC, &param_len, &lenvar);
        offset += lenvar;

        if (param_len > INT32_MAX) {
            THROW(ReportedBoundsError);
        }

        tvbuff_t *value_tvb = tvb_new_subset_length(tvb, offset, (int)param_len);

        if (!setup) {
            proto_item_set_text(param_ti, "Session Parameter: 0x%" PRIx64, param_id);
            proto_tree_add_item(param_tree, hf_moql_session_parameter_value, value_tvb, 0,
                                (int)param_len, ENC_NA);
        } else {
            proto_item_set_text(param_ti, "Setup Parameter: %s",
                                val64_to_str_wmem(pinfo->pool, param_id,
                                                  moql_setup_parameter_vals,
                                                  "Unknown (0x%" PRIx64 ")"));

            switch (param_id) {
            case MOQL_SETUP_PARAM_PROBE: {
                uint64_t level;

                proto_tree_add_item_ret_varint(param_tree, hf_moql_setup_probe_level, value_tvb, 0,
                                               -1, ENC_VARINT_QUIC, &level, &lenvar);
                proto_item_append_text(param_ti, " = %s",
                                       val64_to_str_wmem(pinfo->pool, level,
                                                         moql_probe_level_vals,
                                                         "Unknown (%" PRIu64 ")"));
                break;
            }
            case MOQL_SETUP_PARAM_PATH: {
                char *path = NULL;

                proto_tree_add_item_ret_display_string(param_tree, hf_moql_setup_path, value_tvb, 0,
                                                       (int)param_len, ENC_UTF_8, pinfo->pool,
                                                       &path);
                proto_item_append_text(param_ti, " = %s", path);
                if (param_len == 0) {
                    proto_tree_add_expert_format(param_tree, pinfo, &ei_moql_protocol_violation,
                                                 value_tvb, 0, 0,
                                                 "The Path Parameter must not be empty");
                }
                break;
            }
            default:
                proto_tree_add_item(param_tree, hf_moql_setup_parameter_value, value_tvb, 0,
                                    (int)param_len, ENC_NA);
                break;
            }
        }

        offset += (int)param_len;
        proto_item_set_len(param_ti, offset - param_start);
    }

    return offset - start;
}

static void
moql_dissect_setup(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    uint64_t param_count;
    int      offset = 0;

    offset += moql_add_varint(tvb, tree, offset, hf_moql_setup_parameter_count, &param_count);

    offset += moql_dissect_parameters(tvb, pinfo, tree, offset, param_count, true);

    if (tvb_reported_length_remaining(tvb, offset) > 0) {
        proto_tree_add_expert_remaining(tree, pinfo, &ei_moql_extra_data, tvb, offset);
    }
}

/* Note the negotiated version, which selects the layout of several messages. */
static void
moql_set_version(packet_info *pinfo, moql_session_t *session, proto_item *ti, uint64_t version)
{
    if ((version & MOQL_VERSION_MASK) != MOQL_VERSION_BASE) {
        expert_add_info_format(pinfo, ti, &ei_moql_unknown_version,
                               "Unknown moq-lite version (0x%" PRIx64 ")", version);
        return;
    }

    if (!PINFO_FD_VISITED(pinfo)) {
        session->version = (unsigned)(version - MOQL_VERSION_BASE);
        session->version_known = true;
    }
}

/*
 * SESSION_CLIENT offers a list of versions, SESSION_SERVER selects one; both
 * are followed by a parameter list. They only exist in moq-lite-02 and earlier.
 */
static int
moql_dissect_session(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *msg_ti,
                     moql_session_t *session, bool from_client)
{
    uint64_t version_count = 1, param_count;
    uint32_t lenvar;
    int      offset = 0;

    if (from_client) {
        offset += moql_add_varint(tvb, tree, offset, hf_moql_version_count, &version_count);
    }

    for (uint64_t i = 0; i < version_count; i++) {
        proto_item *ti;
        uint64_t    version;

        ti = proto_tree_add_item_ret_varint(tree, hf_moql_version, tvb, offset, -1,
                                           ENC_VARINT_QUIC, &version, &lenvar);
        offset += lenvar;
        proto_item_append_text(msg_ti, "%s%s", i == 0 ? ": " : ", ",
                               val64_to_str_wmem(pinfo->pool, version, moql_version_vals,
                                                 "0x%" PRIx64));
        /*
         * The server's selected version is the one in use; a single version
         * offered by the client is a usable fallback if the response to it was
         * not captured.
         */
        if (!from_client || (version_count == 1 && !session->version_known)) {
            moql_set_version(pinfo, session, ti, version);
        }
    }

    offset += moql_add_varint(tvb, tree, offset, hf_moql_session_parameter_count, &param_count);

    offset += moql_dissect_parameters(tvb, pinfo, tree, offset, param_count, false);

    return offset;
}

static int
moql_dissect_announce(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                                proto_item *msg_ti, bool add_col_info, bool broadcast)
{
    const char *suffix = NULL;
    uint64_t    status, hop_count, hops_seen = 0;
    int         offset = 0;

    offset += moql_add_varint(tvb, tree, offset, hf_moql_announce_status, &status);

    offset += moql_add_string(tvb, pinfo, tree, offset, hf_moql_broadcast_path_suffix, &suffix);

    if (broadcast) {
        offset += moql_add_varint(tvb, tree, offset, hf_moql_hop_count, &hop_count);

        while (hops_seen < hop_count && tvb_reported_length_remaining(tvb, offset) > 0) {
            offset += moql_add_varint(tvb, tree, offset, hf_moql_hop_id, NULL);
            hops_seen++;
        }
        if (hops_seen != hop_count) {
            proto_tree_add_expert_format(tree, pinfo, &ei_moql_protocol_violation, tvb, offset, 0,
                                         "Hop Count (%" PRIu64 ") does not match the number of Hop ID "
                                         "entries (%" PRIu64 ")", hop_count, hops_seen);
        }
    }

    proto_item_append_text(msg_ti, ": %s %s",
                           val64_to_str_wmem(pinfo->pool, status, moql_announce_status_vals,
                                             "Unknown (%" PRIu64 ")"),
                           suffix);
    if (add_col_info) {
        col_append_fstr(pinfo->cinfo, COL_INFO, "(%s %s)",
                        val64_to_str_wmem(pinfo->pool, status, moql_announce_status_vals, "%" PRIu64),
                        suffix);
    }

    return offset;
}

/*
 * Add a Group Start or Group End field, which is either 0 (meaning latest or
 * unbounded) or the absolute group sequence plus one.
 */
static int
moql_add_relative_group(tvbuff_t *tvb, proto_tree *tree, int offset, int hf, const char *zero_text)
{
    proto_item *ti;
    uint64_t    value;
    uint32_t    lenvar;

    ti = proto_tree_add_item_ret_varint(tree, hf, tvb, offset, -1, ENC_VARINT_QUIC, &value, &lenvar);
    if (value == 0) {
        proto_item_append_text(ti, " (%s)", zero_text);
    } else {
        proto_item_append_text(ti, " (group %" PRIu64 ")", value - 1);
    }

    return lenvar;
}

/* The subscriber properties shared by SUBSCRIBE and SUBSCRIBE_UPDATE. */
static int
moql_dissect_subscribe_properties(tvbuff_t *tvb, proto_tree *tree, int offset, bool legacy)
{
    int      start = offset;

    proto_tree_add_item(tree, hf_moql_subscriber_priority, tvb, offset, 1, ENC_NA);
    offset += 1;
    if (legacy) {
        return offset - start;
    }
    proto_tree_add_item(tree, hf_moql_subscriber_ordered, tvb, offset, 1, ENC_NA);
    offset += 1;
    offset += moql_add_varint(tvb, tree, offset, hf_moql_subscriber_max_latency, NULL);
    offset += moql_add_relative_group(tvb, tree, offset, hf_moql_group_start, "latest");
    offset += moql_add_relative_group(tvb, tree, offset, hf_moql_group_end, "unbounded");

    return offset - start;
}

/* Exact fractional seconds, without overflowing remainder * 10^9.
 * QUIC timescales are at most 2^62-1, so 3 * timescale fits in uint64_t. */
static int
moql_timestamp_nsecs(int64_t timestamp, uint64_t timescale)
{
    int64_t fraction = timestamp % (int64_t)timescale;
    uint64_t magnitude = fraction < 0 ? (uint64_t)-fraction : (uint64_t)fraction;
    uint64_t remainder = 0;
    unsigned nsecs = 0;

    for (unsigned bit = 1U << 29; bit != 0; bit >>= 1) {
        remainder = 2 * remainder + ((1000000000U & bit) ? magnitude : 0);
        nsecs = 2 * nsecs + (unsigned)(remainder / timescale);
        remainder %= timescale;
    }
    return fraction < 0 ? -(int)nsecs : (int)nsecs;
}

/*
 * Add the absolute timestamp of a frame, accumulated from the per frame deltas,
 * and its wall clock equivalent if the track's timescale is known.
 */
static void
moql_add_frame_timestamp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *msg_ti,
                         moql_session_t *session, moql_stream_t *stream, uint64_t abs_offset,
                         int64_t delta, int payload_len)
{
    proto_item *ti;
    moql_timestamp_t *memoized, current;
    int64_t timestamp;

    memoized = (moql_timestamp_t *)wmem_map_lookup(stream->frame_timestamps, &abs_offset);
    if (memoized != NULL) {
        current = *memoized;
    } else {
        current = stream->timestamp;
        current.overflow = current.overflow || ckd_add(&current.value, current.value, delta);
        if (!PINFO_FD_VISITED(pinfo)) {
            uint64_t *key = wmem_new(wmem_file_scope(), uint64_t);
            moql_timestamp_t *value = wmem_new(wmem_file_scope(), moql_timestamp_t);

            *key = abs_offset;
            *value = current;
            wmem_map_insert(stream->frame_timestamps, key, value);
            stream->timestamp = current;
        }
    }

    if (current.overflow) {
        proto_tree_add_expert_format(tree, pinfo, &ei_moql_protocol_violation, tvb, 0, 0,
                                    "Frame timestamp overflow; absolute timestamp is unknown");
        return;
    }
    timestamp = current.value;

    ti = proto_tree_add_int64(tree, hf_moql_frame_timestamp, tvb, 0, 0, timestamp);
    proto_item_set_generated(ti);

    /*
     * The timestamp is expressed in the track's timescale, which is only known
     * once the TRACK_INFO of the track has been seen.
     */
    const char *broadcast_path = stream->broadcast_path;
    const char *track_name = stream->track_name;

    if (stream->subscription != NULL) {
        broadcast_path = stream->subscription->broadcast_path;
        track_name = stream->subscription->track_name;
    }

    moql_track_t *track = moql_track_lookup(session, pinfo, broadcast_path, track_name);
    if (track != NULL && track->timescale != 0) {
        nstime_t ts;

        ts.secs = (time_t)(timestamp / (int64_t)track->timescale);
        ts.nsecs = moql_timestamp_nsecs(timestamp, track->timescale);
        ti = proto_tree_add_time(tree, hf_moql_frame_time, tvb, 0, 0, &ts);
        proto_item_set_generated(ti);

        ti = proto_tree_add_uint(tree, hf_moql_track_info_frame, tvb, 0, 0, track->frame_num);
        proto_item_set_generated(ti);
    }

    proto_item_append_text(msg_ti, ": Timestamp %" PRId64 ", %d byte%s payload",
                           timestamp, payload_len, plurality(payload_len, "", "s"));
}

/*
 * Dissect a single message. Returns the number of bytes consumed, or 0 if the
 * message is incomplete (in which case desegmentation has been requested) or
 * cannot be dissected.
 */
static int
moql_dissect_message(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset,
                     quic_stream_info *stream_info, moql_session_t *session,
                     moql_stream_t *stream, bool from_opener, bool add_col_info)
{
    proto_item *msg_ti, *ti;
    proto_tree *msg_tree;
    uint64_t    abs_offset = stream_info->offset + (uint64_t)offset;
    uint64_t    msg_len, wire_type = 0;
    uint32_t    lenvar, type_len = 0, delta_len = 0;
    int         dir = from_opener ? 0 : 1;
    int         cursor = offset;
    int64_t     delta = 0;
    bool        leading;
    bool        legacy = session->version <= MOQL_VERSION_LEGACY_MAX;

    if (stream->body_offset_known[dir]) {
        leading = abs_offset < stream->body_offset[dir];
    } else {
        leading = abs_offset == (from_opener ? stream->data_start : 0);
    }

    moql_message_type_t msg_type;
    switch (QUIC_STREAM_TYPE(stream_info->stream_id)) {
    case QUIC_STREAM_CLIENT_BIDI:
    case QUIC_STREAM_SERVER_BIDI:
        msg_type = moql_expected_bidi_message(stream->stream_type, from_opener, leading, legacy);
        break;
    default:
        msg_type = moql_expected_uni_message(stream->stream_type, leading, legacy);
        break;
    }

    if (msg_type == MOQL_MSG_NONE) {
        proto_tree_add_expert_remaining(tree, pinfo, &ei_moql_unexpected_message, tvb, offset);
        if (add_col_info) {
            col_append_sep_str(pinfo->cinfo, COL_INFO, ", ", "Unexpected data");
        }
        return 0;
    }

    /*
     * Messages on the publisher side of a Subscribe stream carry an explicit
     * type varint, and the timestamp delta of a FRAME precedes its length.
     */
    if (msg_type == MOQL_MSG_SUBSCRIBE_RESPONSE) {
        if (!moql_try_get_varint(tvb, cursor, &wire_type, &type_len)) {
            goto desegment;
        }
        cursor += type_len;
        switch (wire_type) {
        case MOQL_SUBSCRIBE_OK:
            msg_type = MOQL_MSG_SUBSCRIBE_OK;
            break;
        case MOQL_SUBSCRIBE_END:
            msg_type = MOQL_MSG_SUBSCRIBE_END;
            break;
        case MOQL_SUBSCRIBE_DROP:
            msg_type = MOQL_MSG_SUBSCRIBE_DROP;
            break;
        default:
            proto_tree_add_expert_format_remaining(tree, pinfo, &ei_moql_unexpected_message, tvb,
                                                   offset, "Unknown Subscribe stream message type "
                                                   "(0x%" PRIx64 ")", wire_type);
            if (add_col_info) {
                col_append_sep_str(pinfo->cinfo, COL_INFO, ", ", "Unknown message type");
            }
            return 0;
        }
    } else if (msg_type == MOQL_MSG_FRAME && session->version >= 5) {
        /* The frame timestamp was added in draft 05. */
        uint64_t zigzag;

        if (!moql_try_get_varint(tvb, cursor, &zigzag, &delta_len)) {
            goto desegment;
        }
        delta = moql_zigzag_decode(zigzag);
        cursor += delta_len;
    }

    int length_offset = cursor;
    if (!moql_try_get_varint(tvb, cursor, &msg_len, &lenvar)) {
        goto desegment;
    }
    cursor += lenvar;

    int header_len = cursor - offset;
    if (msg_len > (uint64_t)(INT32_MAX - header_len)) {
        proto_tree_add_expert_format_remaining(tree, pinfo, &ei_moql_protocol_violation, tvb, offset,
                                     "Message Length (%" PRIu64 ") is too large", msg_len);
        return 0;
    }

    int total_len = header_len + (int)msg_len;
    int available = (int)tvb_reported_length_remaining(tvb, offset);
    if (available < total_len) {
        /* Nothing more will arrive once the sender has closed the stream. */
        if (moql_desegment && pinfo->can_desegment && !stream_info->fin) {
            pinfo->desegment_offset = offset;
            pinfo->desegment_len = total_len - available;
            return 0;
        }
        /* Without reassembly the remainder of the message cannot be shown. */
        proto_tree_add_expert_format_remaining(tree, pinfo, &ei_moql_incomplete_message, tvb, offset,
                                     "%s message is incomplete: %d of %d bytes",
                                     val_to_str_const(msg_type, moql_message_type_vals, "Unknown"),
                                     available, total_len);
        if (add_col_info) {
            col_append_sep_fstr(pinfo->cinfo, COL_INFO, ", ", "%s[incomplete]",
                                val_to_str_const(msg_type, moql_message_type_vals, "Unknown"));
        }
        return 0;
    }

    msg_ti = proto_tree_add_item(tree, hf_moql_message, tvb, offset, total_len, ENC_NA);
    msg_tree = proto_item_add_subtree(msg_ti, ett_moql_message);
    proto_item_set_text(msg_ti, "%s",
                        val_to_str_const(msg_type, moql_message_type_vals, "Unknown"));

    ti = proto_tree_add_uint(msg_tree, hf_moql_message_type, tvb, offset, 0, msg_type);
    proto_item_set_generated(ti);

    if (add_col_info) {
        col_append_sep_str(pinfo->cinfo, COL_INFO, ", ",
                           val_to_str_const(msg_type, moql_message_type_vals, "Unknown"));
    }

    if (type_len != 0) {
        proto_tree_add_item_ret_varint(msg_tree, hf_moql_subscribe_type, tvb, offset, -1,
                                       ENC_VARINT_QUIC, NULL, &lenvar);
    } else if (delta_len != 0) {
        proto_tree_add_int64(msg_tree, hf_moql_frame_timestamp_delta, tvb, offset,
                             (int)delta_len, delta);
    }
    proto_tree_add_item_ret_varint(msg_tree, hf_moql_message_length, tvb, length_offset, -1,
                                   ENC_VARINT_QUIC, NULL, &lenvar);

    /*
     * Dissect the body against a buffer bounded by the message length, so that
     * a short message is reported instead of running into the next one.
     */
    tvbuff_t *body_tvb = tvb_new_subset_length(tvb, offset + header_len, (int)msg_len);
    int       body_used = 0;
    bool      body_fully_used = false;

    switch (msg_type) {
    case MOQL_MSG_SETUP:
        moql_dissect_setup(body_tvb, pinfo, msg_tree);
        body_fully_used = true;
        break;

    case MOQL_MSG_SESSION_CLIENT:
    case MOQL_MSG_SESSION_SERVER:
        body_used += moql_dissect_session(body_tvb, pinfo, msg_tree, msg_ti, session,
                                          msg_type == MOQL_MSG_SESSION_CLIENT);
        break;

    case MOQL_MSG_SESSION_UPDATE: {
        uint64_t bitrate;

        body_used += moql_add_varint(body_tvb, msg_tree, body_used, hf_moql_session_bitrate, &bitrate);
        proto_item_append_text(msg_ti, ": %" PRIu64 " bit/s", bitrate);
        break;
    }

    case MOQL_MSG_ANNOUNCE_INIT:
        /*
         * ANNOUNCE_INIT (moq-lite-02 and earlier) carried the initial set of
         * broadcast suffixes; its layout is not dissected here.
         */
        if (msg_len > 0) {
            proto_tree_add_item(msg_tree, hf_moql_message_body, body_tvb, 0, (int)msg_len, ENC_NA);
        }
        body_fully_used = true;
        break;

    case MOQL_MSG_ANNOUNCE_PLEASE:
    case MOQL_MSG_ANNOUNCE_REQUEST: {
        const char *prefix = NULL;

        body_used += moql_add_string(body_tvb, pinfo, msg_tree, body_used,
                                     hf_moql_broadcast_path_prefix, &prefix);
        /* Exclude Hop was added in draft 04. */
        if (msg_type == MOQL_MSG_ANNOUNCE_REQUEST && session->version >= 4) {
            body_used += moql_add_varint(body_tvb, msg_tree, body_used, hf_moql_exclude_hop, NULL);
        }

        proto_item_append_text(msg_ti, ": %s", prefix);
        if (add_col_info) {
            col_append_fstr(pinfo->cinfo, COL_INFO, "(%s)", prefix);
        }
        break;
    }

    case MOQL_MSG_ANNOUNCE_OK: {
        uint64_t hop_id, active_count;

        body_used += moql_add_varint(body_tvb, msg_tree, body_used, hf_moql_hop_id, &hop_id);
        body_used += moql_add_varint(body_tvb, msg_tree, body_used, hf_moql_active_count, &active_count);

        proto_item_append_text(msg_ti, ": Hop ID %" PRIu64 ", %" PRIu64 " active broadcast%s",
                               hop_id, active_count, plurality(active_count, "", "s"));
        break;
    }

    case MOQL_MSG_ANNOUNCE:
    case MOQL_MSG_ANNOUNCE_BROADCAST:
        body_used = moql_dissect_announce(body_tvb, pinfo, msg_tree, msg_ti, add_col_info,
                                         msg_type == MOQL_MSG_ANNOUNCE_BROADCAST);
        break;

    case MOQL_MSG_SUBSCRIBE: {
        const char *path = NULL, *name = NULL;
        uint64_t    subscribe_id;

        body_used += moql_add_varint(body_tvb, msg_tree, body_used, hf_moql_subscribe_id, &subscribe_id);
        body_used += moql_add_string(body_tvb, pinfo, msg_tree, body_used,
                                    hf_moql_broadcast_path, &path);
        body_used += moql_add_string(body_tvb, pinfo, msg_tree, body_used,
                                    hf_moql_track_name, &name);
        body_used += moql_dissect_subscribe_properties(body_tvb, msg_tree, body_used, legacy);

        if (!PINFO_FD_VISITED(pinfo) &&
            wmem_map_lookup(session->subscriptions, &subscribe_id) == NULL) {
            moql_subscription_t *subscription = wmem_new0(wmem_file_scope(), moql_subscription_t);
            uint64_t            *key = wmem_new(wmem_file_scope(), uint64_t);

            *key = subscribe_id;
            subscription->frame_num = pinfo->num;
            subscription->broadcast_path = wmem_strdup(wmem_file_scope(), path);
            subscription->track_name = wmem_strdup(wmem_file_scope(), name);
            wmem_map_insert(session->subscriptions, key, subscription);
        }

        proto_item_append_text(msg_ti, ": %s, %s (Subscribe ID %" PRIu64 ")",
                               path, name, subscribe_id);
        if (add_col_info) {
            col_append_fstr(pinfo->cinfo, COL_INFO, "(id=%" PRIu64 " %s %s)", subscribe_id,
                            path, name);
        }
        break;
    }

    case MOQL_MSG_SUBSCRIBE_UPDATE:
        body_used += moql_dissect_subscribe_properties(body_tvb, msg_tree, body_used, legacy);
        break;

    case MOQL_MSG_SUBSCRIBE_OK:
    case MOQL_MSG_SUBSCRIBE_END: {
        uint64_t group;

        if (legacy) {
            /* The resolved start group was added in draft 03. */
            break;
        }
        ti = proto_tree_add_item_ret_varint(msg_tree, hf_moql_group, body_tvb, body_used, -1,
                                           ENC_VARINT_QUIC, &group, &lenvar);
        body_used += lenvar;
        proto_item_append_text(ti, msg_type == MOQL_MSG_SUBSCRIBE_OK ? " (first group)"
                                                                     : " (last group)");
        proto_item_append_text(msg_ti, ": Group %" PRIu64, group);
        if (add_col_info) {
            col_append_fstr(pinfo->cinfo, COL_INFO, "(group=%" PRIu64 ")", group);
        }
        break;
    }

    case MOQL_MSG_SUBSCRIBE_DROP: {
        uint64_t group_start, group_end, error_code;

        body_used += moql_add_varint(body_tvb, msg_tree, body_used, hf_moql_drop_group_start, &group_start);
        body_used += moql_add_varint(body_tvb, msg_tree, body_used, hf_moql_drop_group_end, &group_end);
        body_used += moql_add_varint(body_tvb, msg_tree, body_used, hf_moql_error_code, &error_code);

        proto_item_append_text(msg_ti, ": Groups %" PRIu64 "-%" PRIu64 ", Error Code %" PRIu64,
                               group_start, group_end, error_code);
        if (add_col_info) {
            col_append_fstr(pinfo->cinfo, COL_INFO, "(groups=%" PRIu64 "-%" PRIu64 ")",
                            group_start, group_end);
        }
        break;
    }

    case MOQL_MSG_TRACK_INFO: {
        uint64_t timescale;

        proto_tree_add_item(msg_tree, hf_moql_publisher_priority, body_tvb, body_used, 1, ENC_NA);
        body_used += 1;
        proto_tree_add_item(msg_tree, hf_moql_publisher_ordered, body_tvb, body_used, 1, ENC_NA);
        body_used += 1;
        body_used += moql_add_varint(body_tvb, msg_tree, body_used, hf_moql_publisher_max_latency, NULL);
        ti = proto_tree_add_item_ret_varint(msg_tree, hf_moql_timescale, body_tvb, body_used, -1,
                                           ENC_VARINT_QUIC, &timescale, &lenvar);
        body_used += lenvar;

        if (timescale == 0) {
            expert_add_info_format(pinfo, ti, &ei_moql_protocol_violation,
                                   "The Timescale must not be zero");
        }

        if (stream->broadcast_path != NULL && stream->track_name != NULL) {
            if (!PINFO_FD_VISITED(pinfo) && timescale != 0) {
                moql_track_t *track = wmem_new0(wmem_file_scope(), moql_track_t);
                char         *key = wmem_strdup_printf(wmem_file_scope(), "%zu:%s%s",
                                                       strlen(stream->broadcast_path),
                                                       stream->broadcast_path, stream->track_name);

                track->frame_num = pinfo->num;
                track->timescale = timescale;
                wmem_map_insert(session->tracks, key, track);
            }
            proto_item_append_text(msg_ti, ": %s, %s", stream->broadcast_path,
                                   stream->track_name);
        }
        break;
    }

    case MOQL_MSG_TRACK:
    case MOQL_MSG_FETCH: {
        const char *path = NULL, *name = NULL;
        uint64_t    group_sequence;

        body_used += moql_add_string(body_tvb, pinfo, msg_tree, body_used,
                                    hf_moql_broadcast_path, &path);
        body_used += moql_add_string(body_tvb, pinfo, msg_tree, body_used,
                                    hf_moql_track_name, &name);
        /* FETCH extends TRACK's path/name pair with priority and group. */
        if (msg_type == MOQL_MSG_FETCH) {
            proto_tree_add_item(msg_tree, hf_moql_subscriber_priority, body_tvb, body_used++, 1, ENC_NA);
            body_used += moql_add_varint(body_tvb, msg_tree, body_used, hf_moql_group_sequence, &group_sequence);
        }
        if (!PINFO_FD_VISITED(pinfo)) {
            stream->broadcast_path = wmem_strdup(wmem_file_scope(), path);
            stream->track_name = wmem_strdup(wmem_file_scope(), name);
        }
        proto_item_append_text(msg_ti, ": %s, %s", path, name);
        if (msg_type == MOQL_MSG_FETCH) {
            proto_item_append_text(msg_ti, ", Group %" PRIu64, group_sequence);
        }
        if (add_col_info) {
            col_append_fstr(pinfo->cinfo, COL_INFO, "(%s %s", path, name);
            if (msg_type == MOQL_MSG_FETCH) {
                col_append_fstr(pinfo->cinfo, COL_INFO, " group=%" PRIu64, group_sequence);
            }
            col_append_str(pinfo->cinfo, COL_INFO, ")");
        }
        break;
    }

    case MOQL_MSG_PROBE: {
        uint64_t bitrate, rtt;

        body_used += moql_add_varint(body_tvb, msg_tree, body_used, hf_moql_probe_bitrate, &bitrate);
        body_used += moql_add_varint(body_tvb, msg_tree, body_used, hf_moql_probe_rtt, &rtt);

        proto_item_append_text(msg_ti, ": %" PRIu64 " bit/s, RTT %" PRIu64 " ms", bitrate, rtt);
        break;
    }

    case MOQL_MSG_GOAWAY: {
        const char *uri = NULL;

        body_used += moql_add_string(body_tvb, pinfo, msg_tree, body_used, hf_moql_goaway_uri, &uri);
        if (uri != NULL && uri[0] != '\0') {
            proto_item_append_text(msg_ti, ": %s", uri);
            if (add_col_info) {
                col_append_fstr(pinfo->cinfo, COL_INFO, "(%s)", uri);
            }
        }
        break;
    }

    case MOQL_MSG_GROUP: {
        uint64_t subscribe_id, group_sequence;

        body_used += moql_add_varint(body_tvb, msg_tree, body_used, hf_moql_subscribe_id, &subscribe_id);
        body_used += moql_add_varint(body_tvb, msg_tree, body_used, hf_moql_group_sequence, &group_sequence);

        stream->subscription = (moql_subscription_t *)wmem_map_lookup(session->subscriptions,
                                                                     &subscribe_id);

        proto_item_append_text(msg_ti, ": Subscribe ID %" PRIu64 ", Group %" PRIu64,
                               subscribe_id, group_sequence);
        if (add_col_info) {
            col_append_fstr(pinfo->cinfo, COL_INFO, "(id=%" PRIu64 " group=%" PRIu64 ")",
                            subscribe_id, group_sequence);
        }
        break;
    }

    case MOQL_MSG_FRAME:
        if (session->version >= 5) {
            moql_add_frame_timestamp(body_tvb, pinfo, msg_tree, msg_ti, session, stream, abs_offset,
                                     delta, (int)msg_len);
        } else {
            proto_item_append_text(msg_ti, ": %d byte%s payload", (int)msg_len,
                                   plurality(msg_len, "", "s"));
        }
        if (msg_len > 0) {
            proto_tree_add_item(msg_tree, hf_moql_frame_payload, body_tvb, 0, (int)msg_len, ENC_NA);
        }
        body_fully_used = true;
        break;

    default:
        ws_assert_not_reached();
    }

    if (!body_fully_used && tvb_reported_length_remaining(body_tvb, body_used) > 0) {
        /* Unexpected trailing bytes; a future version may add fields here. */
        proto_tree_add_expert_remaining(msg_tree, pinfo, &ei_moql_extra_data, body_tvb, body_used);
    }

    /* Annotate group data with the track it belongs to. */
    if (msg_type == MOQL_MSG_GROUP || msg_type == MOQL_MSG_FRAME) {
        const char *path = stream->broadcast_path;
        const char *name = stream->track_name;

        if (stream->subscription != NULL) {
            path = stream->subscription->broadcast_path;
            name = stream->subscription->track_name;

            ti = proto_tree_add_uint(msg_tree, hf_moql_subscribe_frame, tvb, offset, 0,
                                     stream->subscription->frame_num);
            proto_item_set_generated(ti);
        }
        if (path != NULL && name != NULL) {
            ti = proto_tree_add_string(msg_tree, hf_moql_broadcast_path, tvb, offset, 0, path);
            proto_item_set_generated(ti);
            ti = proto_tree_add_string(msg_tree, hf_moql_track_name, tvb, offset, 0, name);
            proto_item_set_generated(ti);
        }
    }

    if (leading) {
        stream->body_offset[dir] = abs_offset + (uint64_t)total_len;
        stream->body_offset_known[dir] = true;
    }

    return total_len;

desegment:
    if (moql_desegment && pinfo->can_desegment && !stream_info->fin) {
        pinfo->desegment_offset = offset;
        pinfo->desegment_len = DESEGMENT_ONE_MORE_SEGMENT;
    } else {
        proto_tree_add_expert_format_remaining(tree, pinfo, &ei_moql_incomplete_message, tvb, offset,
                                               "%s message is incomplete",
                                               val_to_str_const(msg_type, moql_message_type_vals,
                                                                "Unknown"));
        if (add_col_info) {
            col_append_sep_fstr(pinfo->cinfo, COL_INFO, ", ", "%s[incomplete]",
                                val_to_str_const(msg_type, moql_message_type_vals, "Unknown"));
        }
    }
    return 0;
}

static int
dissect_moql(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
    quic_stream_info *stream_info = (quic_stream_info *)data;
    moql_session_t   *session;
    moql_stream_t    *stream;
    proto_item       *ti;
    proto_tree       *moql_tree;
    int               offset = 0, messages = 0;
    bool              opener_is_server, is_bidi, from_opener, saved_from_server;

    if (stream_info == NULL) {
        return 0;
    }

    opener_is_server = (stream_info->stream_id & 1) != 0;
    is_bidi = (stream_info->stream_id & 2) == 0;
    from_opener = (stream_info->from_server == opener_is_server);

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "MoQ-Lite");
    /* Only clear the info column for the first moq-lite stream in the packet. */
    if (proto_get_layer_num(pinfo, proto_moq_lite) == 1) {
        col_clear(pinfo->cinfo, COL_INFO);
    }

    session = moql_session_lookup_or_create(pinfo);

    /*
     * Both directions of a bidirectional stream share state, since only the
     * endpoint that opened the stream sends the stream type.
     */
    saved_from_server = stream_info->from_server;
    if (is_bidi) {
        stream_info->from_server = opener_is_server;
    }
    stream = (moql_stream_t *)quic_stream_get_proto_data(pinfo, stream_info);
    if (stream == NULL) {
        stream = wmem_new0(wmem_file_scope(), moql_stream_t);
        stream->stream_type = MOQL_STREAM_TYPE_UNKNOWN;
        stream->frame_timestamps = wmem_map_new(wmem_file_scope(), g_int64_hash, g_int64_equal);
        quic_stream_add_proto_data(pinfo, stream_info, stream);
    }
    stream_info->from_server = saved_from_server;

    ti = proto_tree_add_item(tree, proto_moq_lite, tvb, 0, -1, ENC_NA);
    moql_tree = proto_item_add_subtree(ti, ett_moql);

    const value_string *stream_type_vals = is_bidi ? moql_bidi_stream_type_vals
                                                   : moql_uni_stream_type_vals;

    /* The stream type is the first thing the opener writes on a stream. */
    if (from_opener && stream_info->offset == 0) {
        proto_item *type_ti;
        uint64_t    stream_type;
        uint32_t    lenvar;

        if (!moql_try_get_varint(tvb, offset, &stream_type, &lenvar)) {
            if (moql_desegment && pinfo->can_desegment && !stream_info->fin) {
                pinfo->desegment_offset = offset;
                pinfo->desegment_len = DESEGMENT_ONE_MORE_SEGMENT;
            }
            return tvb_captured_length(tvb);
        }

        bool known = stream_type <= UINT32_MAX &&
                     try_val_to_str((uint32_t)stream_type, stream_type_vals) != NULL;

        type_ti = proto_tree_add_uint64_format_value(moql_tree, hf_moql_stream_type, tvb, offset,
                                                     lenvar, stream_type, "%s (0x%" PRIx64 ")",
                                                     known ? val_to_str_const((uint32_t)stream_type,
                                                                              stream_type_vals, "")
                                                           : "Unknown", stream_type);
        offset += lenvar;

        stream->stream_type = known ? stream_type : MOQL_STREAM_TYPE_UNKNOWN;
        stream->data_start = lenvar;

        if (!known) {
            /*
             * An endpoint resets streams whose type it does not know, so
             * anything that follows cannot be dissected.
             */
            expert_add_info_format(pinfo, type_ti, &ei_moql_unknown_stream_type,
                                   "Unknown %s stream type (0x%" PRIx64 ")",
                                   is_bidi ? "bidirectional" : "unidirectional", stream_type);
        }
    }

    if (stream->stream_type == MOQL_STREAM_TYPE_UNKNOWN) {
        /*
         * Either the start of the stream was not captured, or its type is not
         * known to this dissector.
         */
        if (tvb_reported_length_remaining(tvb, offset) > 0) {
            proto_tree_add_expert_remaining(moql_tree, pinfo, &ei_moql_stream_type_missing, tvb,
                                            offset);
        }
        col_append_sep_str(pinfo->cinfo, COL_INFO, ", ", "Undissected stream data");
        return tvb_captured_length(tvb);
    }

    const char *stream_name = val_to_str_const((uint32_t)stream->stream_type, stream_type_vals,
                                               "Unknown");
    proto_item_append_text(ti, ", %s stream", stream_name);
    col_append_sep_fstr(pinfo->cinfo, COL_INFO, ", ", "%s stream", stream_name);

    while (tvb_reported_length_remaining(tvb, offset) > 0) {
        bool add_col_info = messages < MOQL_MAX_COL_INFO_MESSAGES;
        int  consumed;

        if (!add_col_info && messages == MOQL_MAX_COL_INFO_MESSAGES) {
            col_append_str(pinfo->cinfo, COL_INFO, ", ...");
        }

        consumed = moql_dissect_message(tvb, pinfo, moql_tree, offset, stream_info, session, stream,
                                        from_opener, add_col_info);
        messages++;
        if (consumed <= 0) {
            break;
        }
        offset += consumed;
    }

    return tvb_captured_length(tvb);
}

static int
dissect_moql_datagram(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    moql_session_t      *session;
    moql_subscription_t *subscription;
    proto_item          *ti;
    proto_tree          *moql_tree;
    uint64_t             subscribe_id, group_sequence, timestamp;
    int                  offset = 0;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "MoQ-Lite");
    col_set_str(pinfo->cinfo, COL_INFO, "Group datagram");

    session = moql_session_lookup_or_create(pinfo);

    ti = proto_tree_add_item(tree, proto_moq_lite, tvb, 0, -1, ENC_NA);
    proto_item_append_text(ti, ", Group datagram");
    moql_tree = proto_item_add_subtree(ti, ett_moql);

    offset += moql_add_varint(tvb, moql_tree, offset, hf_moql_subscribe_id, &subscribe_id);
    offset += moql_add_varint(tvb, moql_tree, offset, hf_moql_group_sequence, &group_sequence);
    offset += moql_add_varint(tvb, moql_tree, offset, hf_moql_datagram_timestamp, &timestamp);

    int payload_len = (int)tvb_reported_length_remaining(tvb, offset);
    if (payload_len > 0) {
        proto_tree_add_item(moql_tree, hf_moql_frame_payload, tvb, offset, payload_len, ENC_NA);
    }

    subscription = (moql_subscription_t *)wmem_map_lookup(session->subscriptions, &subscribe_id);
    if (subscription != NULL) {
        ti = proto_tree_add_string(moql_tree, hf_moql_broadcast_path, tvb, 0, 0,
                                   subscription->broadcast_path);
        proto_item_set_generated(ti);
        ti = proto_tree_add_string(moql_tree, hf_moql_track_name, tvb, 0, 0,
                                   subscription->track_name);
        proto_item_set_generated(ti);
        ti = proto_tree_add_uint(moql_tree, hf_moql_subscribe_frame, tvb, 0, 0,
                                 subscription->frame_num);
        proto_item_set_generated(ti);
    }

    if (tvb_reported_length(tvb) > MOQL_MAX_DATAGRAM_SIZE) {
        proto_tree_add_expert_format_remaining(moql_tree, pinfo, &ei_moql_protocol_violation, tvb, 0,
                                     "The datagram body (%u bytes) exceeds the %d byte limit",
                                     tvb_reported_length(tvb), MOQL_MAX_DATAGRAM_SIZE);
    }

    col_append_fstr(pinfo->cinfo, COL_INFO, "(id=%" PRIu64 " group=%" PRIu64
                    " ts=%" PRIu64 " %d byte%s)", subscribe_id, group_sequence, timestamp,
                    payload_len, plurality(payload_len, "", "s"));

    return tvb_captured_length(tvb);
}

void
proto_register_moq_lite(void)
{
    expert_module_t *expert_moql;
    module_t        *moql_module;

    static hf_register_info hf[] = {
        { &hf_moql_stream_type,
          { "Stream Type", "moql.stream_type",
            FT_UINT64, BASE_HEX, NULL, 0x0,
            "The type of transaction carried by this QUIC stream", HFILL }
        },
        { &hf_moql_message,
          { "Message", "moql.message",
            FT_NONE, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_moql_message_type,
          { "Message Type", "moql.message_type",
            FT_UINT32, BASE_DEC, VALS(moql_message_type_vals), 0x0,
            "The message, inferred from the stream type, direction and position", HFILL }
        },
        { &hf_moql_message_length,
          { "Message Length", "moql.message_length",
            FT_UINT64, BASE_DEC, NULL, 0x0,
            "Length of the message payload in bytes", HFILL }
        },
        { &hf_moql_string_length,
          { "String Length", "moql.string_length",
            FT_UINT64, BASE_DEC, NULL, 0x0,
            "Length of the following string in bytes", HFILL }
        },
        { &hf_moql_setup_parameter_count,
          { "Parameter Count", "moql.setup.parameter_count",
            FT_UINT64, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_moql_setup_parameter,
          { "Setup Parameter", "moql.setup.parameter",
            FT_NONE, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_moql_setup_parameter_id,
          { "Parameter ID", "moql.setup.parameter_id",
            FT_UINT64, BASE_HEX | BASE_VAL64_STRING, VALS64(moql_setup_parameter_vals), 0x0,
            NULL, HFILL }
        },
        { &hf_moql_setup_parameter_length,
          { "Parameter Length", "moql.setup.parameter_length",
            FT_UINT64, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_moql_setup_parameter_value,
          { "Parameter Value", "moql.setup.parameter_value",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_moql_setup_probe_level,
          { "Probe Level", "moql.setup.probe_level",
            FT_UINT64, BASE_DEC | BASE_VAL64_STRING, VALS64(moql_probe_level_vals), 0x0,
            "The sender's bandwidth probing capability as a publisher", HFILL }
        },
        { &hf_moql_session_parameter,
          { "Session Parameter", "moql.session.parameter",
            FT_NONE, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_moql_session_parameter_count,
          { "Parameter Count", "moql.session.parameter_count",
            FT_UINT64, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_moql_session_parameter_id,
          { "Parameter ID", "moql.session.parameter_id",
            FT_UINT64, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_moql_session_parameter_length,
          { "Parameter Length", "moql.session.parameter_length",
            FT_UINT64, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_moql_session_parameter_value,
          { "Parameter Value", "moql.session.parameter_value",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_moql_version,
          { "Version", "moql.version",
            FT_UINT64, BASE_HEX | BASE_VAL64_STRING, VALS64(moql_version_vals), 0x0,
            "A moq-lite version, as negotiated by moq-lite-02 and earlier", HFILL }
        },
        { &hf_moql_version_count,
          { "Version Count", "moql.version_count",
            FT_UINT64, BASE_DEC, NULL, 0x0,
            "Number of versions supported by the client", HFILL }
        },
        { &hf_moql_session_bitrate,
          { "Bitrate", "moql.session.bitrate",
            FT_UINT64, BASE_DEC | BASE_UNIT_STRING, UNS(&units_bit_sec), 0x0,
            "The sender's estimated bitrate, 0 is unknown", HFILL }
        },
        { &hf_moql_message_body,
          { "Message Body", "moql.message_body",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            "The undissected body of a message", HFILL }
        },
        { &hf_moql_setup_path,
          { "Path", "moql.setup.path",
            FT_STRING, BASE_NONE, NULL, 0x0,
            "The request path the client wishes to reach", HFILL }
        },
        { &hf_moql_broadcast_path,
          { "Broadcast Path", "moql.broadcast_path",
            FT_STRING, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_moql_broadcast_path_prefix,
          { "Broadcast Path Prefix", "moql.broadcast_path_prefix",
            FT_STRING, BASE_NONE, NULL, 0x0,
            "Interest in any broadcast whose path starts with this prefix", HFILL }
        },
        { &hf_moql_broadcast_path_suffix,
          { "Broadcast Path Suffix", "moql.broadcast_path_suffix",
            FT_STRING, BASE_NONE, NULL, 0x0,
            "Combined with the requested prefix to form the full broadcast path", HFILL }
        },
        { &hf_moql_exclude_hop,
          { "Exclude Hop", "moql.exclude_hop",
            FT_UINT64, BASE_DEC, NULL, 0x0,
            "Skip broadcasts whose path contains this Hop ID", HFILL }
        },
        { &hf_moql_hop_id,
          { "Hop ID", "moql.hop_id",
            FT_UINT64, BASE_DEC, NULL, 0x0,
            "A relay in the path from the origin publisher (0 is unknown)", HFILL }
        },
        { &hf_moql_hop_count,
          { "Hop Count", "moql.hop_count",
            FT_UINT64, BASE_DEC, NULL, 0x0,
            "Number of Hop ID entries that follow", HFILL }
        },
        { &hf_moql_active_count,
          { "Active Count", "moql.active_count",
            FT_UINT64, BASE_DEC, NULL, 0x0,
            "Number of active announcements sent as the initial set", HFILL }
        },
        { &hf_moql_announce_status,
          { "Announce Status", "moql.announce_status",
            FT_UINT64, BASE_DEC | BASE_VAL64_STRING, VALS64(moql_announce_status_vals), 0x0,
            NULL, HFILL }
        },
        { &hf_moql_track_name,
          { "Track Name", "moql.track_name",
            FT_STRING, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_moql_subscribe_id,
          { "Subscribe ID", "moql.subscribe_id",
            FT_UINT64, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_moql_subscriber_priority,
          { "Subscriber Priority", "moql.subscriber_priority",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            "Higher values are transmitted first during congestion", HFILL }
        },
        { &hf_moql_subscriber_ordered,
          { "Subscriber Ordered", "moql.subscriber_ordered",
            FT_UINT8, BASE_DEC, VALS(moql_ordered_vals), 0x0,
            NULL, HFILL }
        },
        { &hf_moql_subscriber_max_latency,
          { "Subscriber Max Latency", "moql.subscriber_max_latency",
            FT_UINT64, BASE_DEC | BASE_UNIT_STRING, UNS(&units_milliseconds), 0x0,
            "How long a non-latest group may remain in flight before it is dropped", HFILL }
        },
        { &hf_moql_group_start,
          { "Group Start", "moql.group_start",
            FT_UINT64, BASE_DEC, NULL, 0x0,
            "The first group to deliver: 0 is the latest group, otherwise the absolute "
            "group sequence plus one", HFILL }
        },
        { &hf_moql_group_end,
          { "Group End", "moql.group_end",
            FT_UINT64, BASE_DEC, NULL, 0x0,
            "The last group to deliver: 0 is unbounded, otherwise the absolute "
            "group sequence plus one", HFILL }
        },
        { &hf_moql_publisher_priority,
          { "Publisher Priority", "moql.publisher_priority",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            "Used only to resolve ties between equal subscriber priorities", HFILL }
        },
        { &hf_moql_publisher_ordered,
          { "Publisher Ordered", "moql.publisher_ordered",
            FT_UINT8, BASE_DEC, VALS(moql_ordered_vals), 0x0,
            NULL, HFILL }
        },
        { &hf_moql_publisher_max_latency,
          { "Publisher Max Latency", "moql.publisher_max_latency",
            FT_UINT64, BASE_DEC | BASE_UNIT_STRING, UNS(&units_milliseconds), 0x0,
            "How long the publisher caches a non-latest group", HFILL }
        },
        { &hf_moql_timescale,
          { "Timescale", "moql.timescale",
            FT_UINT64, BASE_DEC, NULL, 0x0,
            "Frame timestamp units per second", HFILL }
        },
        { &hf_moql_subscribe_type,
          { "Type", "moql.subscribe.type",
            FT_UINT64, BASE_HEX | BASE_VAL64_STRING, VALS64(moql_subscribe_type_vals), 0x0,
            "The message type, as sent by the publisher on a Subscribe stream", HFILL }
        },
        { &hf_moql_group,
          { "Group", "moql.group",
            FT_UINT64, BASE_DEC, NULL, 0x0,
            "An absolute group sequence number", HFILL }
        },
        { &hf_moql_drop_group_start,
          { "Group Start", "moql.drop.group_start",
            FT_UINT64, BASE_DEC, NULL, 0x0,
            "The first absolute group sequence in the dropped range", HFILL }
        },
        { &hf_moql_drop_group_end,
          { "Group End", "moql.drop.group_end",
            FT_UINT64, BASE_DEC, NULL, 0x0,
            "The last absolute group sequence in the dropped range", HFILL }
        },
        { &hf_moql_error_code,
          { "Error Code", "moql.error_code",
            FT_UINT64, BASE_DEC, NULL, 0x0,
            "An application specific error code (0 is no error)", HFILL }
        },
        { &hf_moql_group_sequence,
          { "Group Sequence", "moql.group_sequence",
            FT_UINT64, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_moql_probe_bitrate,
          { "Bitrate", "moql.probe.bitrate",
            FT_UINT64, BASE_DEC | BASE_UNIT_STRING, UNS(&units_bit_sec), 0x0,
            "The target bitrate (subscriber) or estimated bitrate (publisher), 0 is unknown",
            HFILL }
        },
        { &hf_moql_probe_rtt,
          { "RTT", "moql.probe.rtt",
            FT_UINT64, BASE_DEC | BASE_UNIT_STRING, UNS(&units_milliseconds), 0x0,
            "The smoothed round-trip time, 0 is unknown", HFILL }
        },
        { &hf_moql_goaway_uri,
          { "New Session URI", "moql.goaway.uri",
            FT_STRING, BASE_NONE, NULL, 0x0,
            "A URI to reconnect to, empty for no redirect", HFILL }
        },
        { &hf_moql_frame_timestamp_delta,
          { "Timestamp Delta", "moql.frame.timestamp_delta",
            FT_INT64, BASE_DEC, NULL, 0x0,
            "Zigzag encoded delta from the previous frame's timestamp", HFILL }
        },
        { &hf_moql_frame_timestamp,
          { "Timestamp", "moql.frame.timestamp",
            FT_INT64, BASE_DEC, NULL, 0x0,
            "The absolute frame timestamp in the track's timescale", HFILL }
        },
        { &hf_moql_frame_time,
          { "Time", "moql.frame.time",
            FT_RELATIVE_TIME, BASE_NONE, NULL, 0x0,
            "The absolute frame timestamp converted using the track's timescale", HFILL }
        },
        { &hf_moql_frame_payload,
          { "Payload", "moql.frame.payload",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            "An application specific payload, opaque to moq-lite", HFILL }
        },
        { &hf_moql_datagram_timestamp,
          { "Timestamp", "moql.datagram.timestamp",
            FT_UINT64, BASE_DEC, NULL, 0x0,
            "The absolute timestamp of the frame in the track's timescale", HFILL }
        },
        { &hf_moql_subscribe_frame,
          { "Subscribe Frame", "moql.subscribe_frame",
            FT_FRAMENUM, BASE_NONE, NULL, 0x0,
            "The frame containing the SUBSCRIBE for this Subscribe ID", HFILL }
        },
        { &hf_moql_track_info_frame,
          { "Track Info Frame", "moql.track_info_frame",
            FT_FRAMENUM, BASE_NONE, NULL, 0x0,
            "The frame containing the TRACK_INFO used to interpret timestamps", HFILL }
        },
    };

    static int *ett[] = {
        &ett_moql,
        &ett_moql_message,
        &ett_moql_setup_parameter,
        &ett_moql_session_parameter,
    };

    static ei_register_info ei[] = {
        { &ei_moql_unknown_stream_type,
          { "moql.unknown_stream_type", PI_PROTOCOL, PI_WARN,
            "Unknown stream type", EXPFILL }
        },
        { &ei_moql_unknown_version,
          { "moql.unknown_version", PI_PROTOCOL, PI_WARN,
            "Unknown moq-lite version", EXPFILL }
        },
        { &ei_moql_stream_type_missing,
          { "moql.stream_type_missing", PI_UNDECODED, PI_NOTE,
            "Undissected stream data: the stream type is unknown", EXPFILL }
        },
        { &ei_moql_unexpected_message,
          { "moql.unexpected_message", PI_MALFORMED, PI_WARN,
            "Unexpected message for this stream type and direction", EXPFILL }
        },
        { &ei_moql_incomplete_message,
          { "moql.incomplete_message", PI_UNDECODED, PI_NOTE,
            "Incomplete message and reassembly is disabled", EXPFILL }
        },
        { &ei_moql_extra_data,
          { "moql.extra_data", PI_PROTOCOL, PI_NOTE,
            "Unexpected trailing data in the message body", EXPFILL }
        },
        { &ei_moql_protocol_violation,
          { "moql.protocol_violation", PI_PROTOCOL, PI_ERROR,
            "Protocol violation", EXPFILL }
        },
    };

    proto_moq_lite = proto_register_protocol("Media over QUIC Lite", "MoQ-Lite", "moql");

    proto_register_field_array(proto_moq_lite, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
    expert_moql = expert_register_protocol(proto_moq_lite);
    expert_register_field_array(expert_moql, ei, array_length(ei));

    moql_handle = register_dissector("moq-lite", dissect_moql, proto_moq_lite);
    moql_datagram_handle = register_dissector("moq-lite.datagram", dissect_moql_datagram,
                                             proto_moq_lite);

    moql_module = prefs_register_protocol(proto_moq_lite, NULL);
    prefs_register_bool_preference(moql_module, "desegment",
                                   "Reassemble MoQ-Lite messages spanning multiple QUIC frames",
                                   "Whether the MoQ-Lite dissector should reassemble messages "
                                   "spanning multiple QUIC STREAM frames",
                                   &moql_desegment);
}

void
proto_reg_handoff_moq_lite(void)
{
    /* Every draft has its own ALPN token, e.g. "moq-lite-05". */
    for (unsigned version = 0; version <= MOQL_VERSION_LATEST; version++) {
        char *alpn = ws_strdup_printf("moq-lite-%02u", version);

        dissector_add_string("quic.proto", alpn, moql_handle);
        dissector_add_string("quic.proto.datagram", alpn, moql_datagram_handle);
        g_free(alpn);
    }
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
