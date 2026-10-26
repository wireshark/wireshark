/* packet-moqt.c
 * Routines for Media over QUIC Transport (MOQT) dissection
 * draft-ietf-moq-transport-18
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <epan/expert.h>
#include <epan/packet.h>

#include "packet-quic.h"

void proto_register_moqt(void);
void proto_reg_handoff_moqt(void);

#define MOQT_ALPN_DRAFT_18 "moqt-18"

#define MOQT_MSG_REQUEST_UPDATE       0x02
#define MOQT_MSG_SUBSCRIBE            0x03
#define MOQT_MSG_SUBSCRIBE_OK         0x04
#define MOQT_MSG_REQUEST_ERROR        0x05
#define MOQT_MSG_PUBLISH_NAMESPACE    0x06
#define MOQT_MSG_REQUEST_OK           0x07
#define MOQT_MSG_NAMESPACE            0x08
#define MOQT_MSG_PUBLISH_DONE         0x0b
#define MOQT_MSG_TRACK_STATUS         0x0d
#define MOQT_MSG_NAMESPACE_DONE       0x0e
#define MOQT_MSG_PUBLISH_BLOCKED      0x0f
#define MOQT_MSG_GOAWAY               0x10
#define MOQT_MSG_FETCH                0x16
#define MOQT_MSG_FETCH_OK             0x18
#define MOQT_MSG_PUBLISH              0x1d
#define MOQT_MSG_PUBLISH_OK           0x1e
#define MOQT_MSG_SUBSCRIBE_NAMESPACE  0x50
#define MOQT_MSG_SUBSCRIBE_TRACKS     0x51
#define MOQT_MSG_SETUP                0x2f00

#define MOQT_STREAM_FETCH             0x05
#define MOQT_STREAM_PADDING           0x132b3e28
#define MOQT_DATAGRAM_PADDING         0x132b3e29

#define MOQT_REQUEST_ERROR_REDIRECT   0x34

#define MOQT_PARAM_OBJECT_DELIVERY_TIMEOUT    0x02
#define MOQT_PARAM_AUTHORIZATION_TOKEN        0x03
#define MOQT_PARAM_RENDEZVOUS_TIMEOUT         0x04
#define MOQT_PARAM_SUBGROUP_DELIVERY_TIMEOUT  0x06
#define MOQT_PARAM_EXPIRES                    0x08
#define MOQT_PARAM_LARGEST_OBJECT             0x09
#define MOQT_PARAM_FILL_TIMEOUT               0x0a
#define MOQT_PARAM_FORWARD                    0x10
#define MOQT_PARAM_SUBSCRIBER_PRIORITY        0x20
#define MOQT_PARAM_SUBSCRIPTION_FILTER        0x21
#define MOQT_PARAM_GROUP_ORDER                0x22
#define MOQT_PARAM_NEW_GROUP_REQUEST          0x32
#define MOQT_PARAM_TRACK_NAMESPACE_PREFIX     0x34

#define MOQT_SETUP_AUTHORIZATION_TOKEN        0x03

/* Draft 18 subgroup stream types (section 11.4.2). */
#define MOQT_SUBGROUP_PROPERTIES              0x01
#define MOQT_SUBGROUP_ID_MODE                 0x06
#define MOQT_SUBGROUP_ID_ZERO                 0x00
#define MOQT_SUBGROUP_ID_FIRST_OBJECT         0x02
#define MOQT_SUBGROUP_ID_EXPLICIT             0x04
#define MOQT_SUBGROUP_END_OF_GROUP            0x08
#define MOQT_SUBGROUP_TYPE_MARKER             0x10
#define MOQT_SUBGROUP_DEFAULT_PRIORITY        0x20
#define MOQT_SUBGROUP_FIRST_OBJECT            0x40
#define MOQT_SUBGROUP_DEFINED_BITS            0x7f

/* Draft 18 FETCH serialization flags (section 11.4.4). */
#define MOQT_FETCH_SUBGROUP_ID_MODE            0x03
#define MOQT_FETCH_SUBGROUP_ID_EXPLICIT        0x03
#define MOQT_FETCH_OBJECT_ID_DELTA             0x04
#define MOQT_FETCH_GROUP_ID_DELTA              0x08
#define MOQT_FETCH_PRIORITY                    0x10
#define MOQT_FETCH_PROPERTIES                  0x20
#define MOQT_FETCH_DATAGRAM                    0x40
#define MOQT_FETCH_DEFINED_BITS               0x7f
#define MOQT_FETCH_END_NONEXISTENT_RANGE       0x8c
#define MOQT_FETCH_END_UNKNOWN_RANGE          0x10c

/* Draft 18 OBJECT_DATAGRAM types (section 11.3.1). */
#define MOQT_DATAGRAM_PROPERTIES              0x01
#define MOQT_DATAGRAM_END_OF_GROUP            0x02
#define MOQT_DATAGRAM_ZERO_OBJECT_ID          0x04
#define MOQT_DATAGRAM_DEFAULT_PRIORITY        0x08
#define MOQT_DATAGRAM_STATUS                  0x20
#define MOQT_DATAGRAM_DEFINED_BITS            0x2f

#define MOQT_OBJECT_NORMAL                    0x00
#define MOQT_OBJECT_END_OF_GROUP              0x03
#define MOQT_OBJECT_END_OF_TRACK              0x04

#define MOQT_FETCH_STANDALONE                 0x01
#define MOQT_FETCH_JOIN_RELATIVE              0x02
#define MOQT_FETCH_JOIN_ABSOLUTE              0x03

#define MOQT_FILTER_ABSOLUTE_START            0x03
#define MOQT_FILTER_ABSOLUTE_RANGE            0x04

static dissector_handle_t moqt_handle;
static dissector_handle_t moqt_datagram_handle;

static int proto_moqt;

static int hf_moqt_stream_type;
static int hf_moqt_message_type;
static int hf_moqt_message_length;
static int hf_moqt_request_id;
static int hf_moqt_track_alias;
static int hf_moqt_namespace_count;
static int hf_moqt_namespace_field_length;
static int hf_moqt_namespace_field;
static int hf_moqt_track_name_length;
static int hf_moqt_track_name;
static int hf_moqt_parameter_count;
static int hf_moqt_parameter_type_delta;
static int hf_moqt_parameter_type;
static int hf_moqt_parameter_uint8;
static int hf_moqt_parameter_varint;
static int hf_moqt_parameter_length;
static int hf_moqt_parameter_value;
static int hf_moqt_setup_option_type_delta;
static int hf_moqt_setup_option_type;
static int hf_moqt_setup_option_length;
static int hf_moqt_setup_option_integer;
static int hf_moqt_setup_option_value;
static int hf_moqt_property_type_delta;
static int hf_moqt_property_type;
static int hf_moqt_property_length;
static int hf_moqt_property_integer;
static int hf_moqt_property_value;
static int hf_moqt_properties_length;
static int hf_moqt_group_id;
static int hf_moqt_group_id_delta;
static int hf_moqt_subgroup_id;
static int hf_moqt_object_id;
static int hf_moqt_object_id_delta;
static int hf_moqt_publisher_priority;
static int hf_moqt_object_status;
static int hf_moqt_object_payload_length;
static int hf_moqt_object_payload;
static int hf_moqt_datagram_type;
static int hf_moqt_serialization_flags;
static int hf_moqt_subgroup_id_mode;
static int hf_moqt_fetch_subgroup_id_mode;
static int hf_moqt_fetch_group_id_delta_present;
static int hf_moqt_fetch_object_id_delta_present;
static int hf_moqt_fetch_priority_present;
static int hf_moqt_fetch_has_properties;
static int hf_moqt_subgroup_has_properties;
static int hf_moqt_subgroup_end_of_group;
static int hf_moqt_subgroup_default_priority;
static int hf_moqt_has_properties;
static int hf_moqt_end_of_group;
static int hf_moqt_zero_object_id;
static int hf_moqt_default_priority;
static int hf_moqt_status_present;
static int hf_moqt_first_object;
static int hf_moqt_fetch_datagram_object;
static int hf_moqt_fetch_type;
static int hf_moqt_end_of_track;
static int hf_moqt_status_code;
static int hf_moqt_stream_count;
static int hf_moqt_retry_interval;
static int hf_moqt_reason_length;
static int hf_moqt_reason;
static int hf_moqt_uri_length;
static int hf_moqt_uri;
static int hf_moqt_timeout;
static int hf_moqt_filter_type;
static int hf_moqt_end_group_delta;
static int hf_moqt_alias_type;
static int hf_moqt_token_alias;
static int hf_moqt_token_type;
static int hf_moqt_token_value;
static int hf_moqt_padding;
static int hf_moqt_unparsed;

static int ett_moqt;
static int ett_moqt_message;
static int ett_moqt_namespace;
static int ett_moqt_location;
static int ett_moqt_parameters;
static int ett_moqt_parameter;
static int ett_moqt_setup_options;
static int ett_moqt_setup_option;
static int ett_moqt_properties;
static int ett_moqt_property;
static int ett_moqt_stream_header;
static int ett_moqt_object;
static int ett_moqt_subgroup_type_flags;
static int ett_moqt_datagram_flags;
static int ett_moqt_serialization_flags;

static expert_field ei_moqt_truncated;
static expert_field ei_moqt_unknown_message;
static expert_field ei_moqt_unknown_stream;
static expert_field ei_moqt_invalid_type;
static expert_field ei_moqt_invalid_length;
static expert_field ei_moqt_unknown_parameter;
static expert_field ei_moqt_namespace_too_large;
static expert_field ei_moqt_nonzero_padding;
static expert_field ei_moqt_stream_head_missing;
static expert_field ei_moqt_empty_properties;
static expert_field ei_moqt_object_id_overflow;

static const val64_string moqt_stream_type_vals[] = {
    { MOQT_MSG_SETUP,      "Control (SETUP)" },
    { MOQT_STREAM_FETCH,   "FETCH_HEADER" },
    { MOQT_STREAM_PADDING, "PADDING" },
    { 0, NULL }
};

/* Display names are derived from the draft's descriptors during registration. */
static const val64_string *moqt_message_type_vals;
static const val64_string *moqt_parameter_type_vals;

static const val64_string moqt_setup_option_type_vals[] = {
    { 0x01, "PATH" },
    { MOQT_SETUP_AUTHORIZATION_TOKEN, "AUTHORIZATION_TOKEN" },
    { 0x04, "MAX_AUTH_TOKEN_CACHE_SIZE" },
    { 0x05, "AUTHORITY" },
    { 0x07, "MOQT_IMPLEMENTATION" },
    { 0, NULL }
};

static const val64_string moqt_property_type_vals[] = {
    { 0x02, "OBJECT_DELIVERY_TIMEOUT" },
    { 0x04, "MAX_CACHE_DURATION" },
    { 0x06, "SUBGROUP_DELIVERY_TIMEOUT" },
    { 0x0b, "IMMUTABLE" },
    { 0x0e, "DEFAULT_PUBLISHER_PRIORITY" },
    { 0x22, "DEFAULT_PUBLISHER_GROUP_ORDER" },
    { 0x30, "DYNAMIC_GROUPS" },
    { 0x3c, "PRIOR_GROUP_ID_GAP" },
    { 0x3e, "PRIOR_OBJECT_ID_GAP" },
    { 0, NULL }
};

static const val64_string moqt_object_status_vals[] = {
    { 0x00, "Normal" },
    { 0x03, "End of Group" },
    { 0x04, "End of Track" },
    { 0, NULL }
};

static const val64_string moqt_fetch_type_vals[] = {
    { 0x01, "Standalone Fetch" },
    { 0x02, "Relative Joining Fetch" },
    { 0x03, "Absolute Joining Fetch" },
    { 0, NULL }
};

static const val64_string moqt_filter_type_vals[] = {
    { 0x01, "Next Group Start" },
    { 0x02, "Largest Object" },
    { 0x03, "Absolute Start" },
    { 0x04, "Absolute Range" },
    { 0, NULL }
};

static const val64_string moqt_alias_type_vals[] = {
    { 0x00, "Delete" },
    { 0x01, "Register" },
    { 0x02, "Use Alias" },
    { 0x03, "Use Value" },
    { 0, NULL }
};

static const value_string moqt_subgroup_id_mode_vals[] = {
    { 0, "Zero" },
    { 1, "First Object ID" },
    { 2, "Explicit" },
    { 3, "Reserved" },
    { 0, NULL }
};

static const value_string moqt_fetch_subgroup_id_mode_vals[] = {
    { 0, "Zero" },
    { 1, "Prior Object's Subgroup ID" },
    { 2, "Prior Object's Subgroup ID Plus One" },
    { 3, "Explicit" },
    { 0, NULL }
};

static int * const moqt_subgroup_type_fields[] = {
    &hf_moqt_subgroup_has_properties,
    &hf_moqt_subgroup_id_mode,
    &hf_moqt_subgroup_end_of_group,
    &hf_moqt_subgroup_default_priority,
    &hf_moqt_first_object,
    NULL
};

static int * const moqt_fetch_flag_fields[] = {
    &hf_moqt_fetch_datagram_object,
    &hf_moqt_fetch_subgroup_id_mode,
    &hf_moqt_fetch_object_id_delta_present,
    &hf_moqt_fetch_group_id_delta_present,
    &hf_moqt_fetch_priority_present,
    &hf_moqt_fetch_has_properties,
    NULL
};

typedef enum {
    MOQT_STREAM_UNKNOWN,
    MOQT_STREAM_CONTROL,
    MOQT_STREAM_REQUEST,
    MOQT_STREAM_SUBGROUP,
    MOQT_STREAM_FETCH_DATA,
    MOQT_STREAM_PADDING_DATA,
    MOQT_STREAM_KIND_COUNT
} moqt_stream_kind_t;

typedef enum {
    MOQT_DISSECT,
    MOQT_MEASURE
} moqt_parse_phase_t;

typedef struct moqt_draft moqt_draft_t;

/*
 * The header describes this stream only. Track Alias is valid for subgroups;
 * fetch_request_id is valid for FETCH streams and is never used as an alias.
 * Publisher Priority is meaningful only when priority_present is true.
 */
typedef struct {
    bool present;
    uint64_t type;
    uint64_t track_alias;
    uint64_t fetch_request_id;
    uint64_t group_id;
    unsigned subgroup_id_mode;
    uint8_t publisher_priority;
    bool priority_present;
} moqt_stream_header_t;

/*
 * Mutable subgroup state: object_id is valid once object_seen is true.
 * Subgroup ID may be known from the header before any Object is decoded, or
 * resolved from the first Object when the header selects that mode.
 */
typedef struct {
    bool object_seen;
    uint64_t object_id;
    bool subgroup_id_known;
    uint64_t subgroup_id;
} moqt_subgroup_state_t;

typedef struct {
    moqt_stream_kind_t kind;
    moqt_stream_header_t header;
    moqt_subgroup_state_t subgroup;
} moqt_stream_state_t;

/*
 * QUIC owns a separate application-data pointer for each stream direction.
 * All persistent data below has capture lifetime. latest advances only after
 * complete PDUs on the first pass; before_pdu stores immutable snapshots keyed
 * by absolute stream offset. Redissection reads those snapshots and never
 * advances latest. Exported PDUs instead use packet-local state.
 */
typedef struct {
    const moqt_draft_t *draft;
    moqt_stream_state_t latest;
    wmem_map_t *before_pdu;
} moqt_stream_t;

typedef struct {
    tvbuff_t *tvb;
    packet_info *pinfo;
    proto_tree *tree;
    const moqt_draft_t *draft;
    moqt_parse_phase_t phase;
    int offset;
    int end;
    int needed;
    bool failed;
} moqt_cursor_t;

typedef void (*moqt_parameter_decoder_t)(moqt_cursor_t *);
typedef void (*moqt_message_decoder_t)(moqt_cursor_t *,
                                       const moqt_stream_state_t *);
typedef void (*moqt_pdu_parser_t)(moqt_cursor_t *, moqt_stream_state_t *);

typedef enum {
    MOQT_PARAMETER_UINT8,
    MOQT_PARAMETER_INTEGER,
    MOQT_PARAMETER_LOCATION,
    MOQT_PARAMETER_NAMESPACE,
    MOQT_PARAMETER_LENGTH_PREFIXED
} moqt_parameter_encoding_t;

typedef struct {
    uint64_t type;
    const char *name;
    moqt_parameter_encoding_t encoding;
    int *hf;
    moqt_parameter_decoder_t decode;
} moqt_parameter_descriptor_t;

typedef struct {
    uint64_t type;
    const char *name;
    moqt_message_decoder_t decode;
} moqt_message_descriptor_t;

typedef struct {
    moqt_pdu_parser_t header;
    moqt_pdu_parser_t pdu;
} moqt_stream_layout_t;

/*
 * A draft supplies its integer reader, message/parameter descriptors, and
 * stream/datagram parsers. Framing and flag meanings belong to those parsers,
 * not the shared PDU loop. Add a draft by supplying another context and ALPN
 * entry; do not infer a newer wire layout from a draft-18 message number.
 */
struct moqt_draft {
    unsigned version;
    const char *alpn;
    const moqt_message_descriptor_t *messages;
    unsigned message_count;
    const moqt_parameter_descriptor_t *parameters;
    unsigned parameter_count;
    const val64_string *setup_options;
    const val64_string *properties;
    const moqt_stream_layout_t *streams;
    moqt_stream_kind_t (*classify_stream)(uint64_t);
    bool (*read_integer)(tvbuff_t *, int, int, uint64_t *, int *, int *);
    void (*parse_datagram)(moqt_cursor_t *);
};

static const moqt_draft_t moqt_draft18;

typedef enum {
    MOQT_KV_SETUP,
    MOQT_KV_PROPERTY
} moqt_kv_kind_t;

/* Section 1.4.1: a vi64 has one more byte than its leading one bits. */
static int
moqt_vi64_length(uint8_t first)
{
    int length = 1;

    while (length < 9 && (first & (0x100 >> length)) != 0) {
        length++;
    }
    return length;
}

static bool
moqt_draft18_read_integer(tvbuff_t *tvb, int offset, int end,
                          uint64_t *value, int *encoded_length, int *needed)
{
    uint8_t first;
    int length;
    uint64_t decoded;

    if (offset >= end || !tvb_bytes_exist(tvb, offset, 1)) {
        *needed = 1;
        return false;
    }
    first = tvb_get_uint8(tvb, offset);
    length = moqt_vi64_length(first);
    if (length > end - offset) {
        *needed = length - (end - offset);
        return false;
    }
    if (!tvb_bytes_exist(tvb, offset, length)) {
        *needed = 0; /* A truncated capture cannot be repaired by reassembly. */
        return false;
    }

    decoded = length == 9 ? 0 : first & (0xffU >> length);
    for (int i = 1; i < length; i++) {
        decoded = (decoded << 8) | tvb_get_uint8(tvb, offset + i);
    }
    if (value) {
        *value = decoded;
    }
    if (encoded_length) {
        *encoded_length = length;
    }
    return true;
}

static void
moqt_cursor_fail(moqt_cursor_t *cursor, const char *description)
{
    if (cursor->failed) {
        return;
    }
    if (cursor->phase == MOQT_DISSECT) {
        proto_tree_add_expert_format(
            cursor->tree, cursor->pinfo, &ei_moqt_truncated, cursor->tvb,
            cursor->offset, MAX(cursor->end - cursor->offset, 0),
            "Truncated %s", description);
    }
    cursor->offset = cursor->end;
    cursor->failed = true;
}

/* needed > 0 requests more stream bytes; needed == 0 is a malformed length. */
static bool
moqt_cursor_require(moqt_cursor_t *cursor, uint64_t length,
                     const char *description)
{
    if (cursor->failed) {
        return false;
    }
    if (length > INT_MAX) {
        if (cursor->phase == MOQT_DISSECT) {
            proto_tree_add_expert_format(
                cursor->tree, cursor->pinfo, &ei_moqt_invalid_length,
                cursor->tvb, cursor->offset,
                MAX(cursor->end - cursor->offset, 0),
                "%s length (%" PRIu64 ") cannot fit in a tvbuff",
                description, length);
        }
        cursor->needed = 0;
        cursor->failed = true;
        cursor->offset = cursor->end;
        return false;
    }
    if (length > (uint64_t)(cursor->end - cursor->offset)) {
        cursor->needed = (int)length - (cursor->end - cursor->offset);
        moqt_cursor_fail(cursor, description);
        return false;
    }
    if (!tvb_bytes_exist(cursor->tvb, cursor->offset, (int)length)) {
        cursor->needed = 0;
        moqt_cursor_fail(cursor, description);
        return false;
    }
    return true;
}

static bool
moqt_cursor_varint(moqt_cursor_t *cursor, int hf, uint64_t *value,
                   const char *description)
{
    uint64_t decoded;
    int length;

    if (cursor->failed) {
        return false;
    }
    if (!cursor->draft->read_integer(cursor->tvb, cursor->offset,
                                     cursor->end, &decoded, &length,
                                     &cursor->needed)) {
        moqt_cursor_fail(cursor, description);
        return false;
    }
    if (cursor->phase == MOQT_DISSECT && hf >= 0) {
        proto_tree_add_uint64(cursor->tree, hf, cursor->tvb,
                              cursor->offset, length, decoded);
    }
    cursor->offset += length;
    if (value) {
        *value = decoded;
    }
    return true;
}

static bool
moqt_cursor_uint8(moqt_cursor_t *cursor, int hf, uint8_t *value,
                  const char *description)
{
    uint8_t decoded;

    if (!moqt_cursor_require(cursor, 1, description)) {
        return false;
    }
    decoded = tvb_get_uint8(cursor->tvb, cursor->offset);
    if (cursor->phase == MOQT_DISSECT && hf >= 0) {
        proto_tree_add_uint(cursor->tree, hf, cursor->tvb,
                            cursor->offset, 1, decoded);
    }
    cursor->offset++;
    if (value) {
        *value = decoded;
    }
    return true;
}

static bool
moqt_cursor_uint16(moqt_cursor_t *cursor, int hf, uint16_t *value,
                   const char *description)
{
    uint16_t decoded;

    if (!moqt_cursor_require(cursor, 2, description)) {
        return false;
    }
    decoded = tvb_get_ntohs(cursor->tvb, cursor->offset);
    if (cursor->phase == MOQT_DISSECT && hf >= 0) {
        proto_tree_add_uint(cursor->tree, hf, cursor->tvb,
                            cursor->offset, 2, decoded);
    }
    cursor->offset += 2;
    *value = decoded;
    return true;
}

static bool
moqt_cursor_bytes(moqt_cursor_t *cursor, int hf, uint64_t length,
                  const char *description, unsigned encoding)
{
    if (!moqt_cursor_require(cursor, length, description)) {
        return false;
    }
    if (cursor->phase == MOQT_DISSECT && hf >= 0) {
        proto_tree_add_item(cursor->tree, hf, cursor->tvb,
                            cursor->offset, (int)length, encoding);
    }
    cursor->offset += (int)length;
    return true;
}

static void
moqt_cursor_finish_nested(moqt_cursor_t *cursor, const moqt_cursor_t *nested)
{
    cursor->offset = nested->offset;
    cursor->needed = nested->needed;
    cursor->failed = nested->failed;
}

/* Reserve a bounded value, leaving the parent at the following wire field. */
static bool
moqt_cursor_block(moqt_cursor_t *cursor, int hf_length,
                  moqt_cursor_t *nested, const char *description)
{
    uint64_t length;

    if (!moqt_cursor_varint(cursor, hf_length, &length, description) ||
        !moqt_cursor_require(cursor, length, description)) {
        return false;
    }
    *nested = *cursor;
    nested->end = cursor->offset + (int)length;
    cursor->offset = nested->end;
    return true;
}

static bool
moqt_cursor_length_prefixed(moqt_cursor_t *cursor, int hf_length,
                            int hf_value, uint64_t *length,
                            const char *description, unsigned encoding)
{
    moqt_cursor_t value;
    int value_length;

    if (!moqt_cursor_block(cursor, hf_length, &value, description)) {
        return false;
    }
    value_length = value.end - value.offset;
    moqt_cursor_bytes(&value, hf_value, value_length, description, encoding);
    moqt_cursor_finish_nested(cursor, &value);
    if (length && !cursor->failed) {
        *length = value_length;
    }
    return !cursor->failed;
}

static void
moqt_cursor_remainder(moqt_cursor_t *cursor, int hf)
{
    if (!cursor->failed && cursor->offset < cursor->end) {
        moqt_cursor_bytes(cursor, hf, cursor->end - cursor->offset,
                          "remaining bytes", ENC_NA);
    }
}

static void
moqt_add_generated_uint64(moqt_cursor_t *cursor, int hf, uint64_t value)
{
    proto_item *item;

    if (cursor->phase == MOQT_MEASURE) {
        return;
    }
    item = proto_tree_add_uint64(cursor->tree, hf, cursor->tvb,
                                 cursor->offset, 0, value);
    proto_item_set_generated(item);
}

/* The same checked delta encoding is used by parameters and Key-Value-Pairs. */
static bool
moqt_cursor_type_delta(moqt_cursor_t *cursor, int hf_delta, int hf_type,
                       uint64_t *previous_type, const char *description)
{
    uint64_t delta;
    int start = cursor->offset;

    if (!moqt_cursor_varint(cursor, hf_delta, &delta, description)) {
        return false;
    }
    if (delta > UINT64_MAX - *previous_type) {
        if (cursor->phase == MOQT_DISSECT) {
            proto_tree_add_expert(cursor->tree, cursor->pinfo,
                                  &ei_moqt_invalid_type, cursor->tvb,
                                  start, cursor->offset - start);
        }
        cursor->failed = true;
        cursor->offset = cursor->end;
        return false;
    }
    *previous_type += delta;
    moqt_add_generated_uint64(cursor, hf_type, *previous_type);
    return true;
}

static bool
moqt_dissect_namespace(moqt_cursor_t *cursor, const char *label)
{
    proto_item *item;
    moqt_cursor_t nested;
    uint64_t count;
    int start = cursor->offset;

    if (cursor->failed) {
        return false;
    }
    nested = *cursor;
    nested.tree = proto_tree_add_subtree_format(
        cursor->tree, cursor->tvb, start, -1, ett_moqt_namespace,
        &item, "%s", label);
    if (!moqt_cursor_varint(&nested, hf_moqt_namespace_count, &count,
                            "track namespace field count")) {
        moqt_cursor_finish_nested(cursor, &nested);
        return false;
    }
    if (count > 32 && cursor->phase == MOQT_DISSECT) {
        proto_tree_add_expert_format(
            nested.tree, cursor->pinfo, &ei_moqt_namespace_too_large,
            cursor->tvb, start, nested.offset - start,
            "Track namespace has %" PRIu64 " fields; maximum is 32", count);
    }
    for (uint64_t i = 0; i < count && !nested.failed; i++) {
        moqt_cursor_length_prefixed(&nested, hf_moqt_namespace_field_length,
                                     hf_moqt_namespace_field, NULL,
                                     "track namespace field", ENC_NA);
    }
    proto_item_set_len(item, nested.offset - start);
    moqt_cursor_finish_nested(cursor, &nested);
    return !cursor->failed;
}

static void
moqt_dissect_track_name(moqt_cursor_t *cursor)
{
    moqt_cursor_length_prefixed(cursor, hf_moqt_track_name_length,
                                hf_moqt_track_name, NULL,
                                "track name", ENC_NA);
}

static void
moqt_dissect_full_track_name(moqt_cursor_t *cursor)
{
    moqt_dissect_namespace(cursor, "Track Namespace");
    moqt_dissect_track_name(cursor);
}

static void
moqt_dissect_location(moqt_cursor_t *cursor, const char *label)
{
    proto_item *item;
    moqt_cursor_t location;
    int start = cursor->offset;

    if (cursor->failed) {
        return;
    }
    location = *cursor;
    location.tree = proto_tree_add_subtree_format(
        cursor->tree, cursor->tvb, start, -1, ett_moqt_location,
        &item, "%s", label);
    moqt_cursor_varint(&location, hf_moqt_group_id, NULL, "location group ID");
    moqt_cursor_varint(&location, hf_moqt_object_id, NULL, "location object ID");
    proto_item_set_len(item, location.offset - start);
    moqt_cursor_finish_nested(cursor, &location);
}

static void
moqt_dissect_token(moqt_cursor_t *cursor)
{
    uint64_t alias_type;

    if (!moqt_cursor_varint(cursor, hf_moqt_alias_type, &alias_type,
                            "authorization token alias type")) {
        return;
    }
    switch (alias_type) {
    case 0: /* DELETE_ALIAS */
    case 1: /* REGISTER_ALIAS */
    case 2: /* USE_ALIAS */
        moqt_cursor_varint(cursor, hf_moqt_token_alias, NULL,
                           "authorization token alias");
        break;
    default:
        break;
    }
    if (alias_type == 1 || alias_type == 3) {
        moqt_cursor_varint(cursor, hf_moqt_token_type, NULL,
                           "authorization token type");
        moqt_cursor_remainder(cursor, hf_moqt_token_value);
    }
}

static void
moqt_dissect_subscription_filter(moqt_cursor_t *cursor)
{
    uint64_t type;

    if (!moqt_cursor_varint(cursor, hf_moqt_filter_type, &type,
                            "subscription filter type")) {
        return;
    }
    if (type == MOQT_FILTER_ABSOLUTE_START ||
        type == MOQT_FILTER_ABSOLUTE_RANGE) {
        moqt_dissect_location(cursor, "Start Location");
    }
    if (type == MOQT_FILTER_ABSOLUTE_RANGE) {
        moqt_cursor_varint(cursor, hf_moqt_end_group_delta, NULL,
                           "subscription filter end group delta");
    }
}

static void
moqt_dissect_largest_object(moqt_cursor_t *cursor)
{
    moqt_dissect_location(cursor, "Largest Object");
}

static void
moqt_dissect_namespace_prefix(moqt_cursor_t *cursor)
{
    /* Section 10.2.14 uses the namespace directly, without an outer length. */
    moqt_dissect_namespace(cursor, "Track Namespace Prefix");
}

/* Section 10.2: type, name, wire encoding and display/decoder stay together. */
static const moqt_parameter_descriptor_t moqt_draft18_parameters[] = {
    { MOQT_PARAM_OBJECT_DELIVERY_TIMEOUT, "OBJECT_DELIVERY_TIMEOUT",
      MOQT_PARAMETER_INTEGER, &hf_moqt_parameter_varint, NULL },
    { MOQT_PARAM_AUTHORIZATION_TOKEN, "AUTHORIZATION_TOKEN",
      MOQT_PARAMETER_LENGTH_PREFIXED, NULL, moqt_dissect_token },
    { MOQT_PARAM_RENDEZVOUS_TIMEOUT, "RENDEZVOUS_TIMEOUT",
      MOQT_PARAMETER_INTEGER, &hf_moqt_parameter_varint, NULL },
    { MOQT_PARAM_SUBGROUP_DELIVERY_TIMEOUT, "SUBGROUP_DELIVERY_TIMEOUT",
      MOQT_PARAMETER_INTEGER, &hf_moqt_parameter_varint, NULL },
    { MOQT_PARAM_EXPIRES, "EXPIRES",
      MOQT_PARAMETER_INTEGER, &hf_moqt_parameter_varint, NULL },
    { MOQT_PARAM_LARGEST_OBJECT, "LARGEST_OBJECT",
      MOQT_PARAMETER_LOCATION, NULL, moqt_dissect_largest_object },
    { MOQT_PARAM_FILL_TIMEOUT, "FILL_TIMEOUT",
      MOQT_PARAMETER_INTEGER, &hf_moqt_parameter_varint, NULL },
    { MOQT_PARAM_FORWARD, "FORWARD",
      MOQT_PARAMETER_UINT8, &hf_moqt_parameter_uint8, NULL },
    { MOQT_PARAM_SUBSCRIBER_PRIORITY, "SUBSCRIBER_PRIORITY",
      MOQT_PARAMETER_UINT8, &hf_moqt_parameter_uint8, NULL },
    { MOQT_PARAM_SUBSCRIPTION_FILTER, "SUBSCRIPTION_FILTER",
      MOQT_PARAMETER_LENGTH_PREFIXED, NULL, moqt_dissect_subscription_filter },
    { MOQT_PARAM_GROUP_ORDER, "GROUP_ORDER",
      MOQT_PARAMETER_UINT8, &hf_moqt_parameter_uint8, NULL },
    { MOQT_PARAM_NEW_GROUP_REQUEST, "NEW_GROUP_REQUEST",
      MOQT_PARAMETER_INTEGER, &hf_moqt_parameter_varint, NULL },
    { MOQT_PARAM_TRACK_NAMESPACE_PREFIX, "TRACK_NAMESPACE_PREFIX",
      MOQT_PARAMETER_NAMESPACE, NULL, moqt_dissect_namespace_prefix },
};

static const moqt_parameter_descriptor_t *
moqt_find_parameter(const moqt_draft_t *draft, uint64_t type)
{
    for (unsigned i = 0; i < draft->parameter_count; i++) {
        if (draft->parameters[i].type == type) {
            return &draft->parameters[i];
        }
    }
    return NULL;
}

static void
moqt_dissect_parameter_value(moqt_cursor_t *cursor,
                             const moqt_parameter_descriptor_t *parameter)
{
    moqt_cursor_t value;

    if (cursor->failed) {
        return;
    }
    switch (parameter->encoding) {
    case MOQT_PARAMETER_UINT8:
        moqt_cursor_uint8(cursor, *parameter->hf, NULL, parameter->name);
        break;
    case MOQT_PARAMETER_INTEGER:
        moqt_cursor_varint(cursor, *parameter->hf, NULL, parameter->name);
        break;
    case MOQT_PARAMETER_LOCATION:
    case MOQT_PARAMETER_NAMESPACE:
        parameter->decode(cursor);
        break;
    case MOQT_PARAMETER_LENGTH_PREFIXED:
        if (!moqt_cursor_block(cursor, hf_moqt_parameter_length,
                               &value, parameter->name)) {
            return;
        }
        parameter->decode(&value);
        moqt_cursor_remainder(&value, hf_moqt_parameter_value);
        cursor->failed = value.failed;
        break;
    }
}

static void
moqt_dissect_parameters(moqt_cursor_t *cursor)
{
    proto_item *parameters_item;
    moqt_cursor_t parameters;
    uint64_t count;
    uint64_t previous_type = 0;
    int start;

    if (!moqt_cursor_varint(cursor, hf_moqt_parameter_count, &count,
                            "message parameter count")) {
        return;
    }
    start = cursor->offset;
    parameters = *cursor;
    parameters.tree = proto_tree_add_subtree_format(
        cursor->tree, cursor->tvb, start, -1, ett_moqt_parameters,
        &parameters_item, "Message Parameters (%" PRIu64 ")", count);

    for (uint64_t i = 0; i < count && !parameters.failed; i++) {
        const moqt_parameter_descriptor_t *descriptor;
        proto_item *item;
        moqt_cursor_t parameter = parameters;
        int parameter_start = parameter.offset;

        parameter.tree = proto_tree_add_subtree_format(
            parameters.tree, cursor->tvb, parameter_start, -1,
            ett_moqt_parameter, &item, "Parameter %" PRIu64, i + 1);
        if (moqt_cursor_type_delta(
                &parameter, hf_moqt_parameter_type_delta,
                hf_moqt_parameter_type, &previous_type,
                "message parameter type delta")) {
            descriptor = moqt_find_parameter(cursor->draft, previous_type);
            proto_item_append_text(item, ": %s (0x%" PRIx64 ")",
                                   descriptor ? descriptor->name : "Unknown",
                                   previous_type);
            if (descriptor) {
                moqt_dissect_parameter_value(&parameter, descriptor);
            } else {
                proto_tree_add_expert_format(
                    parameter.tree, cursor->pinfo, &ei_moqt_unknown_parameter,
                    cursor->tvb, parameter.offset,
                    parameter.end - parameter.offset,
                    "Unknown draft-%u message parameter type 0x%" PRIx64
                    "; its value encoding cannot be inferred",
                    cursor->draft->version, previous_type);
                parameter.failed = true;
                parameter.offset = parameter.end;
            }
        }
        proto_item_set_len(item, parameter.offset - parameter_start);
        parameters.offset = parameter.offset;
        parameters.failed = parameter.failed;
    }
    proto_item_set_len(parameters_item, parameters.offset - start);
    cursor->offset = parameters.offset;
    cursor->failed = parameters.failed;
}

typedef struct {
    const char *entry_name;
    int *hf_delta;
    int *hf_type;
    int *hf_length;
    int *hf_integer;
    int *hf_value;
    int *ett_container;
    int *ett_entry;
} moqt_kv_fields_t;

static const moqt_kv_fields_t moqt_setup_fields = {
    "Setup Option",
    &hf_moqt_setup_option_type_delta, &hf_moqt_setup_option_type,
    &hf_moqt_setup_option_length, &hf_moqt_setup_option_integer,
    &hf_moqt_setup_option_value, &ett_moqt_setup_options, &ett_moqt_setup_option
};

static const moqt_kv_fields_t moqt_property_fields = {
    "Property",
    &hf_moqt_property_type_delta, &hf_moqt_property_type,
    &hf_moqt_property_length, &hf_moqt_property_integer,
    &hf_moqt_property_value, &ett_moqt_properties, &ett_moqt_property
};

static void
moqt_dissect_kv_value(moqt_cursor_t *cursor, const moqt_kv_fields_t *fields,
                      moqt_kv_kind_t kind, uint64_t type)
{
    moqt_cursor_t value;
    int length_start = cursor->offset;
    int value_length;

    if ((type & 1) == 0) {
        moqt_cursor_varint(cursor, *fields->hf_integer, NULL,
                           "key-value integer");
        return;
    }
    if (!moqt_cursor_block(cursor, *fields->hf_length,
                           &value, "key-value value")) {
        return;
    }
    value_length = value.end - value.offset;
    if (value_length > UINT16_MAX) {
        proto_tree_add_expert_format(
            value.tree, cursor->pinfo, &ei_moqt_invalid_length,
            cursor->tvb, length_start, value.offset - length_start,
            "%s value length (%d) exceeds 65535 bytes",
            fields->entry_name, value_length);
    }
    if (kind == MOQT_KV_SETUP && type == MOQT_SETUP_AUTHORIZATION_TOKEN) {
        moqt_dissect_token(&value);
    }
    moqt_cursor_remainder(&value, *fields->hf_value);
    cursor->failed = value.failed;
}

/* Section 1.4.3: bounded delta types; odd types have length-prefixed values. */
static void
moqt_dissect_kv_pairs(moqt_cursor_t *cursor, moqt_kv_kind_t kind,
                      const char *label)
{
    const moqt_kv_fields_t *fields =
        kind == MOQT_KV_SETUP ? &moqt_setup_fields : &moqt_property_fields;
    const val64_string *names =
        kind == MOQT_KV_SETUP ? cursor->draft->setup_options
                             : cursor->draft->properties;
    proto_item *container_item;
    moqt_cursor_t container;
    uint64_t previous_type = 0;
    int start = cursor->offset;
    unsigned pair_index = 0;

    if (cursor->failed) {
        return;
    }
    container = *cursor;
    container.tree = proto_tree_add_subtree_format(
        cursor->tree, cursor->tvb, start, -1, *fields->ett_container,
        &container_item, "%s", label);

    while (container.offset < container.end && !container.failed) {
        proto_item *item;
        moqt_cursor_t pair = container;
        int pair_start = pair.offset;

        pair.tree = proto_tree_add_subtree_format(
            container.tree, cursor->tvb, pair_start, -1, *fields->ett_entry,
            &item, "%s %u", fields->entry_name, ++pair_index);
        if (moqt_cursor_type_delta(
                &pair, *fields->hf_delta, *fields->hf_type, &previous_type,
                "key-value type delta")) {
            proto_item_append_text(
                item, ": %s (0x%" PRIx64 ")",
                val64_to_str_const(previous_type, names, "Unknown"),
                previous_type);
            moqt_dissect_kv_value(&pair, fields, kind, previous_type);
        }
        proto_item_set_len(item, pair.offset - pair_start);
        container.offset = pair.offset;
        container.failed = pair.failed;
    }
    proto_item_set_len(container_item, container.offset - start);
    cursor->offset = container.offset;
    cursor->failed = container.failed;
}

static bool
moqt_dissect_object_properties(moqt_cursor_t *cursor, uint64_t *length)
{
    moqt_cursor_t properties;

    if (!moqt_cursor_block(cursor, hf_moqt_properties_length,
                           &properties, "object properties")) {
        return false;
    }
    if (length) {
        *length = properties.end - properties.offset;
    }
    /* Measurement needs the block's extent, not the inner property layout. */
    if (cursor->phase == MOQT_DISSECT) {
        moqt_dissect_kv_pairs(&properties, MOQT_KV_PROPERTY, "Object Properties");
        cursor->failed = properties.failed;
    }
    return !cursor->failed;
}

static void
moqt_dissect_parameters_and_properties(moqt_cursor_t *cursor)
{
    moqt_dissect_parameters(cursor);
    if (!cursor->failed && cursor->offset < cursor->end) {
        moqt_dissect_kv_pairs(cursor, MOQT_KV_PROPERTY, "Track Properties");
    }
}

static void
moqt_dissect_reason_phrase(moqt_cursor_t *cursor)
{
    moqt_cursor_length_prefixed(cursor, hf_moqt_reason_length,
                                hf_moqt_reason, NULL, "reason phrase",
                                ENC_UTF_8 | ENC_NA);
}

static void
moqt_dissect_redirect(moqt_cursor_t *cursor)
{
    moqt_cursor_length_prefixed(cursor, hf_moqt_uri_length, hf_moqt_uri,
                                NULL, "redirect connect URI",
                                ENC_UTF_8 | ENC_NA);
    moqt_dissect_namespace(cursor, "Redirect Track Namespace");
    moqt_dissect_track_name(cursor);
}

/* Draft 18 message bodies: calls below follow the order of fields on the wire. */
static void
moqt_draft18_decode_setup(moqt_cursor_t *cursor,
                          const moqt_stream_state_t *state _U_)
{
    moqt_dissect_kv_pairs(cursor, MOQT_KV_SETUP, "Setup Options");
}

static void
moqt_draft18_decode_goaway(moqt_cursor_t *cursor,
                           const moqt_stream_state_t *state)
{
    moqt_cursor_length_prefixed(cursor, hf_moqt_uri_length, hf_moqt_uri,
                                NULL, "new session URI", ENC_UTF_8 | ENC_NA);
    moqt_cursor_varint(cursor, hf_moqt_timeout, NULL, "GOAWAY timeout");
    if (state->kind == MOQT_STREAM_CONTROL) {
        moqt_cursor_varint(cursor, hf_moqt_request_id, NULL, "GOAWAY request ID");
    }
}

static void
moqt_draft18_decode_request_ok(moqt_cursor_t *cursor,
                               const moqt_stream_state_t *state _U_)
{
    moqt_dissect_parameters_and_properties(cursor);
}

static void
moqt_draft18_decode_request_error(moqt_cursor_t *cursor,
                                  const moqt_stream_state_t *state _U_)
{
    uint64_t code;

    if (!moqt_cursor_varint(cursor, hf_moqt_status_code, &code,
                            "request error code")) {
        return;
    }
    moqt_cursor_varint(cursor, hf_moqt_retry_interval, NULL,
                       "request retry interval");
    moqt_dissect_reason_phrase(cursor);
    if (code == MOQT_REQUEST_ERROR_REDIRECT) {
        moqt_dissect_redirect(cursor);
    }
}

static void
moqt_draft18_decode_track_request(moqt_cursor_t *cursor,
                                  const moqt_stream_state_t *state _U_)
{
    moqt_cursor_varint(cursor, hf_moqt_request_id, NULL, "request ID");
    moqt_dissect_full_track_name(cursor);
    moqt_dissect_parameters(cursor);
}

static void
moqt_draft18_decode_subscribe_ok(moqt_cursor_t *cursor,
                                 const moqt_stream_state_t *state _U_)
{
    moqt_cursor_varint(cursor, hf_moqt_track_alias, NULL, "track alias");
    moqt_dissect_parameters_and_properties(cursor);
}

static void
moqt_draft18_decode_request_update(moqt_cursor_t *cursor,
                                   const moqt_stream_state_t *state _U_)
{
    moqt_cursor_varint(cursor, hf_moqt_request_id, NULL, "request ID");
    moqt_dissect_parameters(cursor);
}

static void
moqt_draft18_decode_publish(moqt_cursor_t *cursor,
                            const moqt_stream_state_t *state _U_)
{
    moqt_cursor_varint(cursor, hf_moqt_request_id, NULL, "request ID");
    moqt_dissect_full_track_name(cursor);
    moqt_cursor_varint(cursor, hf_moqt_track_alias, NULL, "track alias");
    moqt_dissect_parameters_and_properties(cursor);
}

static void
moqt_draft18_decode_publish_done(moqt_cursor_t *cursor,
                                 const moqt_stream_state_t *state _U_)
{
    moqt_cursor_varint(cursor, hf_moqt_status_code, NULL,
                       "publish done status code");
    moqt_cursor_varint(cursor, hf_moqt_stream_count, NULL,
                       "publish done stream count");
    moqt_dissect_reason_phrase(cursor);
}

static void
moqt_draft18_decode_fetch_range(moqt_cursor_t *cursor, uint64_t fetch_type)
{
    switch (fetch_type) {
    case MOQT_FETCH_STANDALONE:
        moqt_dissect_full_track_name(cursor);
        moqt_dissect_location(cursor, "Start Location");
        moqt_dissect_location(cursor, "End Location");
        break;
    case MOQT_FETCH_JOIN_RELATIVE:
    case MOQT_FETCH_JOIN_ABSOLUTE:
        moqt_cursor_varint(cursor, hf_moqt_request_id, NULL,
                           "joining request ID");
        moqt_cursor_varint(cursor, hf_moqt_group_id, NULL, "joining start");
        break;
    default:
        proto_tree_add_expert_format(
            cursor->tree, cursor->pinfo, &ei_moqt_invalid_type, cursor->tvb,
            cursor->offset, 0, "Invalid Fetch Type 0x%" PRIx64, fetch_type);
        break;
    }
}

static void
moqt_draft18_decode_fetch(moqt_cursor_t *cursor,
                          const moqt_stream_state_t *state _U_)
{
    uint64_t fetch_type;

    moqt_cursor_varint(cursor, hf_moqt_request_id, NULL, "request ID");
    if (!moqt_cursor_varint(cursor, hf_moqt_fetch_type, &fetch_type,
                            "fetch type")) {
        return;
    }
    moqt_draft18_decode_fetch_range(cursor, fetch_type);
    moqt_dissect_parameters(cursor);
}

static void
moqt_draft18_decode_fetch_ok(moqt_cursor_t *cursor,
                             const moqt_stream_state_t *state _U_)
{
    moqt_cursor_uint8(cursor, hf_moqt_end_of_track, NULL, "end-of-track flag");
    moqt_dissect_location(cursor, "End Location");
    moqt_dissect_parameters_and_properties(cursor);
}

static void
moqt_draft18_decode_publish_namespace(moqt_cursor_t *cursor,
                                      const moqt_stream_state_t *state _U_)
{
    moqt_cursor_varint(cursor, hf_moqt_request_id, NULL, "request ID");
    moqt_dissect_namespace(cursor, "Track Namespace");
    moqt_dissect_parameters(cursor);
}

static void
moqt_draft18_decode_namespace_suffix(moqt_cursor_t *cursor,
                                     const moqt_stream_state_t *state _U_)
{
    moqt_dissect_namespace(cursor, "Track Namespace Suffix");
}

static void
moqt_draft18_decode_namespace_request(moqt_cursor_t *cursor,
                                      const moqt_stream_state_t *state _U_)
{
    moqt_cursor_varint(cursor, hf_moqt_request_id, NULL, "request ID");
    moqt_dissect_namespace(cursor, "Track Namespace Prefix");
    moqt_dissect_parameters(cursor);
}

static void
moqt_draft18_decode_publish_blocked(moqt_cursor_t *cursor,
                                    const moqt_stream_state_t *state _U_)
{
    moqt_dissect_namespace(cursor, "Track Namespace Suffix");
    moqt_dissect_track_name(cursor);
}

static const moqt_message_descriptor_t moqt_draft18_messages[] = {
    { MOQT_MSG_REQUEST_UPDATE, "REQUEST_UPDATE",
      moqt_draft18_decode_request_update },
    { MOQT_MSG_SUBSCRIBE, "SUBSCRIBE", moqt_draft18_decode_track_request },
    { MOQT_MSG_SUBSCRIBE_OK, "SUBSCRIBE_OK", moqt_draft18_decode_subscribe_ok },
    { MOQT_MSG_REQUEST_ERROR, "REQUEST_ERROR",
      moqt_draft18_decode_request_error },
    { MOQT_MSG_PUBLISH_NAMESPACE, "PUBLISH_NAMESPACE",
      moqt_draft18_decode_publish_namespace },
    { MOQT_MSG_REQUEST_OK, "REQUEST_OK", moqt_draft18_decode_request_ok },
    { MOQT_MSG_NAMESPACE, "NAMESPACE", moqt_draft18_decode_namespace_suffix },
    { MOQT_MSG_PUBLISH_DONE, "PUBLISH_DONE", moqt_draft18_decode_publish_done },
    { MOQT_MSG_TRACK_STATUS, "TRACK_STATUS", moqt_draft18_decode_track_request },
    { MOQT_MSG_NAMESPACE_DONE, "NAMESPACE_DONE",
      moqt_draft18_decode_namespace_suffix },
    { MOQT_MSG_PUBLISH_BLOCKED, "PUBLISH_BLOCKED",
      moqt_draft18_decode_publish_blocked },
    { MOQT_MSG_GOAWAY, "GOAWAY", moqt_draft18_decode_goaway },
    { MOQT_MSG_FETCH, "FETCH", moqt_draft18_decode_fetch },
    { MOQT_MSG_FETCH_OK, "FETCH_OK", moqt_draft18_decode_fetch_ok },
    { MOQT_MSG_PUBLISH, "PUBLISH", moqt_draft18_decode_publish },
    /*
     * Section 10.5 calls PUBLISH_OK a REQUEST_OK alias (0x07), while the
     * draft-18 control-message table also lists 0x1e. Accept both spellings.
     */
    { MOQT_MSG_PUBLISH_OK, "PUBLISH_OK", moqt_draft18_decode_request_ok },
    { MOQT_MSG_SUBSCRIBE_NAMESPACE, "SUBSCRIBE_NAMESPACE",
      moqt_draft18_decode_namespace_request },
    { MOQT_MSG_SUBSCRIBE_TRACKS, "SUBSCRIBE_TRACKS",
      moqt_draft18_decode_namespace_request },
    { MOQT_MSG_SETUP, "SETUP", moqt_draft18_decode_setup },
};

static const moqt_message_descriptor_t *
moqt_find_message(const moqt_draft_t *draft, uint64_t type)
{
    for (unsigned i = 0; i < draft->message_count; i++) {
        if (draft->messages[i].type == type) {
            return &draft->messages[i];
        }
    }
    return NULL;
}

/* Section 10 framing: Type (vi64), Length (16), bounded message body. */
static void
moqt_draft18_parse_message(moqt_cursor_t *cursor, moqt_stream_state_t *state)
{
    const moqt_message_descriptor_t *message;
    const char *name;
    proto_item *item;
    moqt_cursor_t body;
    uint64_t type;
    uint16_t body_length;
    int start = cursor->offset;
    int length_offset;

    if (!moqt_cursor_varint(cursor, -1, &type, "message type")) {
        return;
    }
    length_offset = cursor->offset;
    if (!moqt_cursor_uint16(cursor, -1, &body_length, "message length") ||
        !moqt_cursor_require(cursor, body_length, "message body")) {
        return;
    }
    body = *cursor;
    body.end = body.offset + body_length;
    cursor->offset = body.end;
    if (cursor->phase == MOQT_MEASURE) {
        return; /* No body decoder or state update is needed for framing. */
    }

    message = moqt_find_message(cursor->draft, type);
    name = message ? message->name : "Unknown";
    body.tree = proto_tree_add_subtree_format(
        cursor->tree, cursor->tvb, start, body.end - start, ett_moqt_message,
        &item, "%s, Length: %u", name, body_length);
    proto_tree_add_uint64(body.tree, hf_moqt_message_type, cursor->tvb,
                          start, length_offset - start, type);
    proto_tree_add_uint(body.tree, hf_moqt_message_length, cursor->tvb,
                        length_offset, 2, body_length);
    if (message) {
        message->decode(&body, state);
    } else {
        proto_tree_add_expert_format(
            body.tree, cursor->pinfo, &ei_moqt_unknown_message, cursor->tvb,
            body.offset, body.end - body.offset,
            "Unknown draft-%u control message type 0x%" PRIx64,
            cursor->draft->version, type);
    }
    moqt_cursor_remainder(&body, hf_moqt_unparsed);
    cursor->failed = body.failed;
    col_append_sep_str(cursor->pinfo->cinfo, COL_INFO, ", ", name);
}

static void
moqt_add_subgroup_type_flags(moqt_cursor_t *cursor, int offset,
                             int length, uint64_t type)
{
    proto_item *item;

    if (cursor->phase == MOQT_MEASURE) {
        return;
    }
    item = proto_tree_add_bitmask_value(
        cursor->tree, cursor->tvb, offset, hf_moqt_stream_type,
        ett_moqt_subgroup_type_flags, moqt_subgroup_type_fields, type);
    proto_item_set_len(item, length);
    proto_item_append_text(item, " (SUBGROUP_HEADER)");
}

/* Section 11.4.2: one header layout used for measurement and display. */
static void
moqt_draft18_parse_subgroup_header(moqt_cursor_t *cursor,
                                   moqt_stream_state_t *state)
{
    proto_item *item;
    moqt_cursor_t header = *cursor;
    moqt_stream_header_t decoded = { 0 };
    uint64_t subgroup_id = 0;
    int start = cursor->offset;
    int type_length;

    header.tree = proto_tree_add_subtree(
        cursor->tree, cursor->tvb, start, -1,
        ett_moqt_stream_header, &item, "SUBGROUP_HEADER");
    if (!moqt_cursor_varint(&header, -1, &decoded.type,
                            "subgroup stream type")) {
        goto finished;
    }
    type_length = header.offset - start;
    moqt_add_subgroup_type_flags(&header, start, type_length, decoded.type);
    moqt_cursor_varint(&header, hf_moqt_track_alias, &decoded.track_alias,
                       "track alias");
    moqt_cursor_varint(&header, hf_moqt_group_id, &decoded.group_id, "group ID");
    decoded.subgroup_id_mode =
        (unsigned)(decoded.type & MOQT_SUBGROUP_ID_MODE);
    if (decoded.subgroup_id_mode == MOQT_SUBGROUP_ID_EXPLICIT) {
        moqt_cursor_varint(&header, hf_moqt_subgroup_id, &subgroup_id,
                           "subgroup ID");
    } else if (decoded.subgroup_id_mode == MOQT_SUBGROUP_ID_ZERO) {
        moqt_add_generated_uint64(&header, hf_moqt_subgroup_id, 0);
    }
    decoded.priority_present =
        (decoded.type & MOQT_SUBGROUP_DEFAULT_PRIORITY) == 0;
    if (decoded.priority_present) {
        moqt_cursor_uint8(&header, hf_moqt_publisher_priority,
                          &decoded.publisher_priority, "publisher priority");
    }

    if (!header.failed && cursor->phase == MOQT_DISSECT) {
        decoded.present = true;
        state->header = decoded;
        state->subgroup = (moqt_subgroup_state_t){
            .subgroup_id_known =
                decoded.subgroup_id_mode != MOQT_SUBGROUP_ID_FIRST_OBJECT,
            .subgroup_id = subgroup_id,
        };
        proto_item_append_text(item, ": Track Alias %" PRIu64
                               ", Group %" PRIu64,
                               decoded.track_alias, decoded.group_id);
    }

finished:
    proto_item_set_len(item, header.offset - start);
    moqt_cursor_finish_nested(cursor, &header);
}

static void
moqt_validate_object_status(moqt_cursor_t *cursor, uint64_t status,
                            int offset, int length, uint64_t properties_length)
{
    if (cursor->failed || cursor->phase == MOQT_MEASURE) {
        return;
    }
    if (status != MOQT_OBJECT_NORMAL &&
        status != MOQT_OBJECT_END_OF_GROUP &&
        status != MOQT_OBJECT_END_OF_TRACK) {
        proto_tree_add_expert_format(
            cursor->tree, cursor->pinfo, &ei_moqt_invalid_type, cursor->tvb,
            offset, length, "Invalid draft-%u object status 0x%" PRIx64,
            cursor->draft->version, status);
    }
    /* An empty Properties field is required on property-bearing subgroups. */
    if (properties_length != 0 && status != MOQT_OBJECT_NORMAL) {
        proto_tree_add_expert_format(
            cursor->tree, cursor->pinfo, &ei_moqt_invalid_type, cursor->tvb,
            offset, length,
            "Properties are not permitted on a non-Normal status object");
    }
}

static void
moqt_resolve_subgroup_object_id(moqt_cursor_t *cursor,
                                moqt_stream_state_t *state,
                                uint64_t delta, int object_offset)
{
    moqt_subgroup_state_t *subgroup = &state->subgroup;
    uint64_t object_id = delta;
    int saved_offset;

    if (cursor->phase == MOQT_MEASURE || cursor->failed) {
        return;
    }
    if (subgroup->object_seen) {
        if (subgroup->object_id == UINT64_MAX ||
            delta > UINT64_MAX - subgroup->object_id - 1) {
            proto_tree_add_expert(
                cursor->tree, cursor->pinfo, &ei_moqt_object_id_overflow,
                cursor->tvb, object_offset, cursor->offset - object_offset);
            return;
        }
        object_id = subgroup->object_id + delta + 1;
    }
    subgroup->object_seen = true;
    subgroup->object_id = object_id;

    saved_offset = cursor->offset;
    cursor->offset = object_offset;
    moqt_add_generated_uint64(cursor, hf_moqt_object_id, object_id);
    if (!subgroup->subgroup_id_known &&
        state->header.subgroup_id_mode == MOQT_SUBGROUP_ID_FIRST_OBJECT) {
        subgroup->subgroup_id = object_id;
        subgroup->subgroup_id_known = true;
        moqt_add_generated_uint64(cursor, hf_moqt_subgroup_id, object_id);
    }
    cursor->offset = saved_offset;
}

/* Object ID Delta, [Properties], Payload Length, then Status or Payload. */
static void
moqt_draft18_parse_subgroup_object(moqt_cursor_t *cursor,
                                   moqt_stream_state_t *state)
{
    proto_item *item;
    moqt_cursor_t object = *cursor;
    uint64_t delta;
    uint64_t properties_length = 0;
    uint64_t payload_length;
    uint64_t status = MOQT_OBJECT_NORMAL;
    int start = cursor->offset;
    int status_offset;

    object.tree = proto_tree_add_subtree(
        cursor->tree, cursor->tvb, start, -1, ett_moqt_object,
        &item, "Subgroup Object");
    if (!moqt_cursor_varint(&object, hf_moqt_object_id_delta, &delta,
                            "object ID delta")) {
        goto finished;
    }
    if ((state->header.type & MOQT_SUBGROUP_PROPERTIES) != 0) {
        moqt_dissect_object_properties(&object, &properties_length);
    }
    if (!moqt_cursor_varint(&object, hf_moqt_object_payload_length,
                            &payload_length, "object payload length")) {
        goto finished;
    }
    if (payload_length == 0) {
        status_offset = object.offset;
        moqt_cursor_varint(&object, hf_moqt_object_status, &status,
                           "object status");
        moqt_validate_object_status(&object, status, status_offset,
                                     object.offset - status_offset,
                                     properties_length);
    } else {
        moqt_cursor_bytes(&object, hf_moqt_object_payload, payload_length,
                          "object payload", ENC_NA);
    }
    if (!object.failed && cursor->phase == MOQT_DISSECT) {
        moqt_resolve_subgroup_object_id(&object, state, delta, start);
        proto_item_append_text(
            item, ": ID Delta %" PRIu64 ", Payload %" PRIu64 " byte%s",
            delta, payload_length, payload_length == 1 ? "" : "s");
        if (payload_length == 0) {
            proto_item_append_text(
                item, ", Status: %s",
                val64_to_str_const(status, moqt_object_status_vals, "Unknown"));
        }
        col_append_sep_str(cursor->pinfo->cinfo, COL_INFO, ", ",
                           "Subgroup Object");
    }

finished:
    proto_item_set_len(item, object.offset - start);
    moqt_cursor_finish_nested(cursor, &object);
}

/* Section 11.4.4: Type (vi64), FETCH Request ID (vi64). */
static void
moqt_draft18_parse_fetch_header(moqt_cursor_t *cursor,
                                moqt_stream_state_t *state)
{
    proto_item *item;
    moqt_cursor_t header = *cursor;
    uint64_t type;
    uint64_t request_id;
    int start = cursor->offset;

    header.tree = proto_tree_add_subtree(
        cursor->tree, cursor->tvb, start, -1, ett_moqt_stream_header,
        &item, "FETCH_HEADER");
    moqt_cursor_varint(&header, hf_moqt_stream_type, &type, "fetch stream type");
    moqt_cursor_varint(&header, hf_moqt_request_id, &request_id,
                       "fetch request ID");
    if (!header.failed && cursor->phase == MOQT_DISSECT) {
        state->header = (moqt_stream_header_t){
            .present = true,
            .type = type,
            .fetch_request_id = request_id,
        };
        proto_item_append_text(item, ": Request ID %" PRIu64, request_id);
    }
    proto_item_set_len(item, header.offset - start);
    moqt_cursor_finish_nested(cursor, &header);
}

static void
moqt_add_fetch_flags(moqt_cursor_t *cursor, int offset,
                     int length, uint64_t flags)
{
    proto_item *item;

    if (cursor->phase == MOQT_MEASURE) {
        return;
    }
    item = proto_tree_add_bitmask_value(
        cursor->tree, cursor->tvb, offset, hf_moqt_serialization_flags,
        ett_moqt_serialization_flags, moqt_fetch_flag_fields, flags);
    proto_item_set_len(item, length);
}

/*
 * These are wire deltas, not resolved FETCH locations. Resolving them requires
 * the associated FETCH's Group Order and prior-field state (section 11.4.4.1).
 * Keep that future state separate from the FETCH Request ID in the header.
 */
static void
moqt_draft18_parse_fetch_fields(moqt_cursor_t *cursor, uint64_t flags,
                                uint64_t *payload_length)
{
    if ((flags & MOQT_FETCH_GROUP_ID_DELTA) != 0) {
        moqt_cursor_varint(cursor, hf_moqt_group_id_delta, NULL, "group ID delta");
    }
    if ((flags & MOQT_FETCH_DATAGRAM) == 0 &&
        (flags & MOQT_FETCH_SUBGROUP_ID_MODE) == MOQT_FETCH_SUBGROUP_ID_EXPLICIT) {
        moqt_cursor_varint(cursor, hf_moqt_subgroup_id, NULL, "subgroup ID");
    }
    if ((flags & MOQT_FETCH_OBJECT_ID_DELTA) != 0) {
        moqt_cursor_varint(cursor, hf_moqt_object_id_delta, NULL,
                           "object ID delta");
    }
    if ((flags & MOQT_FETCH_PRIORITY) != 0) {
        moqt_cursor_uint8(cursor, hf_moqt_publisher_priority, NULL,
                          "publisher priority");
    }
    if ((flags & MOQT_FETCH_PROPERTIES) != 0) {
        moqt_dissect_object_properties(cursor, NULL);
    }
    moqt_cursor_length_prefixed(cursor, hf_moqt_object_payload_length,
                                hf_moqt_object_payload, payload_length,
                                "object payload", ENC_NA);
}

static void
moqt_draft18_parse_fetch_object(moqt_cursor_t *cursor,
                                moqt_stream_state_t *state _U_)
{
    proto_item *item;
    moqt_cursor_t object = *cursor;
    uint64_t flags;
    uint64_t payload_length = 0;
    bool end_of_range;
    int start = cursor->offset;
    int flags_length;

    object.tree = proto_tree_add_subtree(
        cursor->tree, cursor->tvb, start, -1, ett_moqt_object,
        &item, "Fetch Object");
    if (!moqt_cursor_varint(&object, -1, &flags, "serialization flags")) {
        goto finished;
    }
    flags_length = object.offset - start;
    end_of_range = flags == MOQT_FETCH_END_NONEXISTENT_RANGE ||
                   flags == MOQT_FETCH_END_UNKNOWN_RANGE;
    if (end_of_range || flags > MOQT_FETCH_DEFINED_BITS) {
        if (cursor->phase == MOQT_DISSECT) {
            proto_tree_add_uint64(object.tree, hf_moqt_serialization_flags,
                                  cursor->tvb, start, flags_length, flags);
        }
    } else {
        moqt_add_fetch_flags(&object, start, flags_length, flags);
    }
    if (end_of_range) {
        moqt_dissect_location(&object, "End of Range Location");
        proto_item_set_text(item, "%s",
                            flags == MOQT_FETCH_END_NONEXISTENT_RANGE
                                ? "End of Non-Existent Range"
                                : "End of Unknown Range");
    } else if (flags > MOQT_FETCH_DEFINED_BITS) {
        if (cursor->phase == MOQT_DISSECT) {
            proto_tree_add_expert_format(
                object.tree, cursor->pinfo, &ei_moqt_invalid_type,
                cursor->tvb, start, flags_length,
                "Invalid draft-%u FETCH serialization flags 0x%" PRIx64,
                cursor->draft->version, flags);
        }
        moqt_cursor_remainder(&object, hf_moqt_unparsed);
    } else {
        moqt_draft18_parse_fetch_fields(&object, flags, &payload_length);
        proto_item_append_text(item, ": Payload %" PRIu64 " byte%s",
                               payload_length, payload_length == 1 ? "" : "s");
    }
    if (!object.failed && cursor->phase == MOQT_DISSECT) {
        col_append_sep_str(cursor->pinfo->cinfo, COL_INFO, ", ", "Fetch Object");
    }

finished:
    proto_item_set_len(item, object.offset - start);
    moqt_cursor_finish_nested(cursor, &object);
}

static void
moqt_draft18_parse_padding_header(moqt_cursor_t *cursor,
                                  moqt_stream_state_t *state)
{
    uint64_t type;

    if (moqt_cursor_varint(cursor, hf_moqt_stream_type, &type,
                           "padding stream type") &&
        cursor->phase == MOQT_DISSECT) {
        state->header = (moqt_stream_header_t){
            .present = true,
            .type = type,
        };
    }
}

static void
moqt_dissect_padding_bytes(moqt_cursor_t *cursor)
{
    int start = cursor->offset;

    moqt_cursor_remainder(cursor, hf_moqt_padding);
    if (cursor->phase == MOQT_MEASURE || cursor->failed) {
        return;
    }
    for (int i = start; i < cursor->end; i++) {
        if (tvb_get_uint8(cursor->tvb, i) != 0) {
            proto_tree_add_expert(cursor->tree, cursor->pinfo,
                                  &ei_moqt_nonzero_padding, cursor->tvb, i, 1);
            break;
        }
    }
}

static void
moqt_draft18_parse_padding(moqt_cursor_t *cursor,
                           moqt_stream_state_t *state _U_)
{
    moqt_dissect_padding_bytes(cursor);
    if (cursor->phase == MOQT_DISSECT) {
        col_append_sep_str(cursor->pinfo->cinfo, COL_INFO, ", ", "Padding Stream");
    }
}

static moqt_stream_kind_t
moqt_draft18_classify_stream(uint64_t type)
{
    if (type == MOQT_MSG_SETUP) {
        return MOQT_STREAM_CONTROL;
    }
    if (type == MOQT_STREAM_FETCH) {
        return MOQT_STREAM_FETCH_DATA;
    }
    if (type == MOQT_STREAM_PADDING) {
        return MOQT_STREAM_PADDING_DATA;
    }
    if (type <= MOQT_SUBGROUP_DEFINED_BITS &&
        (type & MOQT_SUBGROUP_TYPE_MARKER) != 0 &&
        (type & MOQT_SUBGROUP_ID_MODE) != MOQT_SUBGROUP_ID_MODE) {
        return MOQT_STREAM_SUBGROUP;
    }
    return MOQT_STREAM_UNKNOWN;
}

static const moqt_stream_layout_t moqt_draft18_streams[MOQT_STREAM_KIND_COUNT] = {
    [MOQT_STREAM_CONTROL] = { NULL, moqt_draft18_parse_message },
    [MOQT_STREAM_REQUEST] = { NULL, moqt_draft18_parse_message },
    [MOQT_STREAM_SUBGROUP] = {
        moqt_draft18_parse_subgroup_header, moqt_draft18_parse_subgroup_object
    },
    [MOQT_STREAM_FETCH_DATA] = {
        moqt_draft18_parse_fetch_header, moqt_draft18_parse_fetch_object
    },
    [MOQT_STREAM_PADDING_DATA] = {
        moqt_draft18_parse_padding_header, moqt_draft18_parse_padding
    },
};

static void
moqt_add_generated_stream_header(moqt_cursor_t *cursor,
                                 const moqt_stream_state_t *state)
{
    const moqt_stream_header_t *header = &state->header;
    proto_item *item;

    moqt_add_generated_uint64(cursor, hf_moqt_stream_type, header->type);
    switch (state->kind) {
    case MOQT_STREAM_SUBGROUP:
        moqt_add_generated_uint64(cursor, hf_moqt_track_alias,
                                  header->track_alias);
        moqt_add_generated_uint64(cursor, hf_moqt_group_id, header->group_id);
        if (state->subgroup.subgroup_id_known) {
            moqt_add_generated_uint64(cursor, hf_moqt_subgroup_id,
                                      state->subgroup.subgroup_id);
        }
        if (header->priority_present) {
            item = proto_tree_add_uint(cursor->tree, hf_moqt_publisher_priority,
                                        cursor->tvb, cursor->offset, 0,
                                        header->publisher_priority);
            proto_item_set_generated(item);
        }
        break;
    case MOQT_STREAM_FETCH_DATA:
        moqt_add_generated_uint64(cursor, hf_moqt_request_id,
                                  header->fetch_request_id);
        break;
    default:
        break;
    }
}

static void
moqt_request_stream_bytes(packet_info *pinfo, int offset, int needed)
{
    pinfo->desegment_offset = offset;
    pinfo->desegment_len = needed > 0 ? needed : DESEGMENT_ONE_MORE_SEGMENT;
}

static const moqt_stream_state_t *
moqt_stream_snapshot(const moqt_stream_t *stream, uint64_t offset)
{
    return stream->before_pdu
               ? (const moqt_stream_state_t *)wmem_map_lookup(
                     stream->before_pdu, &offset)
               : NULL;
}

/* This is the only place that advances capture-lifetime parsing state. */
static void
moqt_commit_stream_state(moqt_stream_t *stream, packet_info *pinfo,
                          uint64_t offset,
                          const moqt_stream_state_t *before,
                          const moqt_stream_state_t *after)
{
    uint64_t *key;
    moqt_stream_state_t *snapshot;

    if (!stream->before_pdu) {
        stream->latest = *after; /* Packet-local exported-PDU state. */
        return;
    }
    if (PINFO_FD_VISITED(pinfo) || moqt_stream_snapshot(stream, offset)) {
        return;
    }
    key = wmem_new(wmem_file_scope(), uint64_t);
    *key = offset;
    snapshot = wmem_new(wmem_file_scope(), moqt_stream_state_t);
    *snapshot = *before;
    wmem_map_insert(stream->before_pdu, key, snapshot);
    stream->latest = *after;
}

/*
 * One loop for control messages, subgroup Objects, FETCH Objects and padding.
 * A parser measures a PDU using a cursor with no tree and a disposable state
 * copy. A complete PDU is then dissected from the same starting snapshot.
 * Header presence is determined by the absolute stream offset, even when the
 * original header packet is revisited after later Objects have been decoded.
 */
static void
moqt_dissect_stream_pdus(moqt_cursor_t *cursor, quic_stream_info *stream_info,
                         moqt_stream_t *stream)
{
    const moqt_stream_layout_t *layout =
        &cursor->draft->streams[stream->latest.kind];
    moqt_stream_state_t working = stream->latest;
    uint64_t base_offset = stream_info ? stream_info->offset : 0;
    bool first_pdu = true;

    while (cursor->offset < cursor->end) {
        uint64_t stream_offset = base_offset + (uint64_t)cursor->offset;
        const moqt_stream_state_t *snapshot =
            moqt_stream_snapshot(stream, stream_offset);
        moqt_stream_state_t before = snapshot ? *snapshot : working;
        moqt_stream_state_t measured_state = before;
        moqt_cursor_t measured = *cursor;
        moqt_pdu_parser_t parse =
            layout->header && stream_offset == 0 ? layout->header : layout->pdu;
        int start = cursor->offset;

        if (layout->header && stream_offset != 0 && !before.header.present) {
            proto_tree_add_expert(cursor->tree, cursor->pinfo,
                                  &ei_moqt_stream_head_missing, cursor->tvb,
                                  start, cursor->end - start);
            moqt_cursor_remainder(cursor, hf_moqt_unparsed);
            return;
        }
        measured.tree = NULL;
        measured.phase = MOQT_MEASURE;
        parse(&measured, &measured_state);
        if (measured.failed) {
            if (measured.needed > 0) {
                moqt_request_stream_bytes(cursor->pinfo, start, measured.needed);
            } else {
                proto_tree_add_expert(
                    cursor->tree, cursor->pinfo, &ei_moqt_invalid_length,
                    cursor->tvb, start, cursor->end - start);
            }
            return;
        }
        DISSECTOR_ASSERT(measured.offset > start);
        if (first_pdu && layout->header && stream_offset != 0) {
            moqt_add_generated_stream_header(cursor, &before);
        }

        working = before;
        cursor->failed = false;
        parse(cursor, &working);
        moqt_commit_stream_state(stream, cursor->pinfo,
                                  stream_offset, &before, &working);
        /* A malformed inner value still has the measured outer PDU boundary. */
        cursor->offset = measured.offset;
        cursor->failed = false;
        first_pdu = false;
    }
}

/* Exported PDUs lack QUIC metadata; recognize an entire framed control PDU. */
static bool
moqt_looks_like_control_pdu(moqt_cursor_t *cursor, uint64_t type)
{
    moqt_stream_state_t state = { .kind = MOQT_STREAM_REQUEST };
    moqt_cursor_t measured = *cursor;

    if (!moqt_find_message(cursor->draft, type)) {
        return false;
    }
    measured.tree = NULL;
    measured.phase = MOQT_MEASURE;
    cursor->draft->streams[MOQT_STREAM_REQUEST].pdu(&measured, &state);
    return !measured.failed && measured.offset == measured.end;
}

static int
moqt_dissect_stream(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                    quic_stream_info *stream_info, const moqt_draft_t *draft)
{
    moqt_stream_t local_stream = { .draft = draft };
    moqt_stream_t *stream;
    moqt_cursor_t cursor;
    proto_item *protocol_item;
    uint64_t first_type;
    int needed = 0;

    /* QUIC's FIN-only path can pass the following frame/padding as this tvb. */
    if (stream_info && stream_info->fin_only) {
        return 0;
    }
    if (tvb_reported_length(tvb) == 0) {
        return 0;
    }

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "MOQT");
    protocol_item = proto_tree_add_item(tree, proto_moqt, tvb, 0, -1, ENC_NA);
    cursor = (moqt_cursor_t){
        .tvb = tvb,
        .pinfo = pinfo,
        .tree = proto_item_add_subtree(protocol_item, ett_moqt),
        .draft = draft,
        .phase = MOQT_DISSECT,
        .end = (int)tvb_reported_length(tvb),
    };

    stream = &local_stream;
    if (stream_info) {
        stream = (moqt_stream_t *)quic_stream_get_proto_data(pinfo, stream_info);
        if (!stream) {
            stream = wmem_new0(wmem_file_scope(), moqt_stream_t);
            stream->draft = draft;
            stream->before_pdu =
                wmem_map_new(wmem_file_scope(), g_int64_hash, g_int64_equal);
            quic_stream_add_proto_data(pinfo, stream_info, stream);
        }
    }
    cursor.draft = stream->draft;

    if (stream->latest.kind == MOQT_STREAM_UNKNOWN) {
        if (stream_info && stream_info->offset != 0) {
            proto_tree_add_expert(cursor.tree, pinfo,
                                  &ei_moqt_stream_head_missing, tvb, 0, -1);
            call_data_dissector(tvb, pinfo, cursor.tree);
            return tvb_captured_length(tvb);
        }
        if (stream_info &&
            (QUIC_STREAM_TYPE(stream_info->stream_id) == QUIC_STREAM_CLIENT_BIDI ||
             QUIC_STREAM_TYPE(stream_info->stream_id) == QUIC_STREAM_SERVER_BIDI)) {
            stream->latest.kind = MOQT_STREAM_REQUEST;
        } else {
            if (!cursor.draft->read_integer(tvb, 0, cursor.end,
                                            &first_type, NULL, &needed)) {
                moqt_request_stream_bytes(pinfo, 0, needed);
                return tvb_captured_length(tvb);
            }
            if (!stream_info && moqt_looks_like_control_pdu(&cursor, first_type)) {
                stream->latest.kind =
                    cursor.draft->classify_stream(first_type) == MOQT_STREAM_CONTROL
                        ? MOQT_STREAM_CONTROL : MOQT_STREAM_REQUEST;
            } else {
                stream->latest.kind = cursor.draft->classify_stream(first_type);
            }
            stream->latest.header.type = first_type;
        }
    }

    if (stream->latest.kind == MOQT_STREAM_UNKNOWN) {
        proto_tree_add_expert_format(
            cursor.tree, pinfo, &ei_moqt_unknown_stream, tvb, 0, -1,
            "Unknown draft-%u unidirectional stream type 0x%" PRIx64,
            cursor.draft->version, stream->latest.header.type);
        call_data_dissector(tvb, pinfo, cursor.tree);
    } else {
        moqt_dissect_stream_pdus(&cursor, stream_info, stream);
    }
    return tvb_captured_length(tvb);
}

static int
dissect_moqt(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
    /* Future ALPN entry points pass their own draft context to this helper. */
    return moqt_dissect_stream(tvb, pinfo, tree, (quic_stream_info *)data,
                               &moqt_draft18);
}

static void
moqt_add_datagram_type_flags(moqt_cursor_t *cursor, int length, uint64_t type)
{
    proto_item *item;
    proto_tree *tree;

    tree = proto_tree_add_subtree(cursor->tree, cursor->tvb, 0, length,
                                  ett_moqt_datagram_flags, &item,
                                  "OBJECT_DATAGRAM Type Fields");
    proto_tree_add_boolean(tree, hf_moqt_has_properties, cursor->tvb, 0, length,
                           (type & MOQT_DATAGRAM_PROPERTIES) != 0);
    proto_tree_add_boolean(tree, hf_moqt_end_of_group, cursor->tvb, 0, length,
                           (type & MOQT_DATAGRAM_END_OF_GROUP) != 0);
    proto_tree_add_boolean(tree, hf_moqt_zero_object_id, cursor->tvb, 0, length,
                           (type & MOQT_DATAGRAM_ZERO_OBJECT_ID) != 0);
    proto_tree_add_boolean(tree, hf_moqt_default_priority, cursor->tvb, 0, length,
                           (type & MOQT_DATAGRAM_DEFAULT_PRIORITY) != 0);
    proto_tree_add_boolean(tree, hf_moqt_status_present, cursor->tvb, 0, length,
                           (type & MOQT_DATAGRAM_STATUS) != 0);
}

static void
moqt_draft18_parse_datagram_object(moqt_cursor_t *cursor, uint64_t type)
{
    uint64_t properties_length = 0;
    uint64_t status = MOQT_OBJECT_NORMAL;
    int properties_offset;
    int status_offset;

    moqt_cursor_varint(cursor, hf_moqt_track_alias, NULL, "track alias");
    moqt_cursor_varint(cursor, hf_moqt_group_id, NULL, "group ID");
    if ((type & MOQT_DATAGRAM_ZERO_OBJECT_ID) == 0) {
        moqt_cursor_varint(cursor, hf_moqt_object_id, NULL, "object ID");
    } else if (!cursor->failed) {
        moqt_add_generated_uint64(cursor, hf_moqt_object_id, 0);
    }
    if ((type & MOQT_DATAGRAM_DEFAULT_PRIORITY) == 0) {
        moqt_cursor_uint8(cursor, hf_moqt_publisher_priority, NULL,
                          "publisher priority");
    }
    if ((type & MOQT_DATAGRAM_PROPERTIES) != 0) {
        properties_offset = cursor->offset;
        if (moqt_dissect_object_properties(cursor, &properties_length) &&
            properties_length == 0) {
            proto_tree_add_expert_format(
                cursor->tree, cursor->pinfo, &ei_moqt_empty_properties,
                cursor->tvb, properties_offset,
                cursor->offset - properties_offset,
                "OBJECT_DATAGRAM has the PROPERTIES bit set with an empty "
                "Properties field");
        }
    }
    if ((type & MOQT_DATAGRAM_STATUS) != 0) {
        status_offset = cursor->offset;
        moqt_cursor_varint(cursor, hf_moqt_object_status, &status, "object status");
        moqt_validate_object_status(cursor, status, status_offset,
                                     cursor->offset - status_offset,
                                     properties_length);
    } else {
        moqt_cursor_remainder(cursor, hf_moqt_object_payload);
    }
}

static void
moqt_draft18_parse_datagram(moqt_cursor_t *cursor)
{
    uint64_t type;
    int type_length;

    if (!moqt_cursor_varint(cursor, hf_moqt_datagram_type, &type,
                            "datagram type")) {
        return;
    }
    type_length = cursor->offset;
    if (type == MOQT_DATAGRAM_PADDING) {
        moqt_dissect_padding_bytes(cursor);
        col_append_sep_str(cursor->pinfo->cinfo, COL_INFO, ", ", "Padding");
        return;
    }
    if ((type & ~((uint64_t)MOQT_DATAGRAM_DEFINED_BITS)) != 0 ||
        ((type & MOQT_DATAGRAM_STATUS) != 0 &&
         (type & MOQT_DATAGRAM_END_OF_GROUP) != 0)) {
        proto_tree_add_expert_format(
            cursor->tree, cursor->pinfo, &ei_moqt_invalid_type, cursor->tvb,
            0, type_length, "Invalid draft-%u datagram type 0x%" PRIx64,
            cursor->draft->version, type);
        moqt_cursor_remainder(cursor, hf_moqt_unparsed);
        return;
    }
    moqt_add_datagram_type_flags(cursor, type_length, type);
    moqt_draft18_parse_datagram_object(cursor, type);
}

static const moqt_draft_t moqt_draft18 = {
    .version = 18,
    .alpn = MOQT_ALPN_DRAFT_18,
    .messages = moqt_draft18_messages,
    .message_count = array_length(moqt_draft18_messages),
    .parameters = moqt_draft18_parameters,
    .parameter_count = array_length(moqt_draft18_parameters),
    .setup_options = moqt_setup_option_type_vals,
    .properties = moqt_property_type_vals,
    .streams = moqt_draft18_streams,
    .classify_stream = moqt_draft18_classify_stream,
    .read_integer = moqt_draft18_read_integer,
    .parse_datagram = moqt_draft18_parse_datagram,
};

static int
dissect_moqt_datagram(tvbuff_t *tvb, packet_info *pinfo,
                      proto_tree *tree, void *data _U_)
{
    proto_item *item;
    moqt_cursor_t cursor;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "MOQT");
    col_append_sep_str(pinfo->cinfo, COL_INFO, ", ", "Object Datagram");
    item = proto_tree_add_item(tree, proto_moqt, tvb, 0, -1, ENC_NA);
    cursor = (moqt_cursor_t){
        .tvb = tvb,
        .pinfo = pinfo,
        .tree = proto_item_add_subtree(item, ett_moqt),
        .draft = &moqt_draft18,
        .phase = MOQT_DISSECT,
        .end = (int)tvb_reported_length(tvb),
    };
    cursor.draft->parse_datagram(&cursor);
    return tvb_captured_length(tvb);
}

void
proto_register_moqt(void)
{
    val64_string *message_names = (val64_string *)wmem_alloc(
        wmem_epan_scope(),
        sizeof(val64_string) * (moqt_draft18.message_count + 1));
    val64_string *parameter_names = (val64_string *)wmem_alloc(
        wmem_epan_scope(),
        sizeof(val64_string) * (moqt_draft18.parameter_count + 1));

    for (unsigned i = 0; i < moqt_draft18.message_count; i++) {
        message_names[i] = (val64_string){
            moqt_draft18.messages[i].type, moqt_draft18.messages[i].name
        };
    }
    message_names[moqt_draft18.message_count] = (val64_string){ 0, NULL };
    moqt_message_type_vals = message_names;

    for (unsigned i = 0; i < moqt_draft18.parameter_count; i++) {
        parameter_names[i] = (val64_string){
            moqt_draft18.parameters[i].type, moqt_draft18.parameters[i].name
        };
    }
    parameter_names[moqt_draft18.parameter_count] = (val64_string){ 0, NULL };
    moqt_parameter_type_vals = parameter_names;

    /* Wireshark retains pointers into this array, so it must remain static. */
    static hf_register_info hf[] = {
        { &hf_moqt_stream_type,
          { "Stream Type", "moqt.stream.type",
            FT_UINT64, BASE_HEX | BASE_VAL64_STRING,
            VALS64(moqt_stream_type_vals), 0x0,
            NULL, HFILL }
        },
        { &hf_moqt_message_type,
          { "Message Type", "moqt.message.type",
            FT_UINT64, BASE_HEX | BASE_VAL64_STRING,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_moqt_message_length,
          { "Message Length", "moqt.message.length",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            "Length of the control message payload", HFILL }
        },
        { &hf_moqt_request_id,
          { "Request ID", "moqt.request_id",
            FT_UINT64, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_moqt_track_alias,
          { "Track Alias", "moqt.track_alias",
            FT_UINT64, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_moqt_namespace_count,
          { "Number of Track Namespace Fields", "moqt.namespace.count",
            FT_UINT64, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_moqt_namespace_field_length,
          { "Track Namespace Field Length", "moqt.namespace.field.length",
            FT_UINT64, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_moqt_namespace_field,
          { "Track Namespace Field", "moqt.namespace.field",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_moqt_track_name_length,
          { "Track Name Length", "moqt.track_name.length",
            FT_UINT64, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_moqt_track_name,
          { "Track Name", "moqt.track_name",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_moqt_parameter_count,
          { "Number of Parameters", "moqt.parameter.count",
            FT_UINT64, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_moqt_parameter_type_delta,
          { "Parameter Type Delta", "moqt.parameter.type_delta",
            FT_UINT64, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_moqt_parameter_type,
          { "Parameter Type", "moqt.parameter.type",
            FT_UINT64, BASE_HEX | BASE_VAL64_STRING,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_moqt_parameter_uint8,
          { "Parameter Value", "moqt.parameter.uint8",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_moqt_parameter_varint,
          { "Parameter Value", "moqt.parameter.varint",
            FT_UINT64, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_moqt_parameter_length,
          { "Parameter Length", "moqt.parameter.length",
            FT_UINT64, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_moqt_parameter_value,
          { "Parameter Value", "moqt.parameter.value",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_moqt_setup_option_type_delta,
          { "Setup Option Type Delta", "moqt.setup.option.type_delta",
            FT_UINT64, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_moqt_setup_option_type,
          { "Setup Option Type", "moqt.setup.option.type",
            FT_UINT64, BASE_HEX | BASE_VAL64_STRING,
            VALS64(moqt_setup_option_type_vals), 0x0,
            NULL, HFILL }
        },
        { &hf_moqt_setup_option_length,
          { "Setup Option Length", "moqt.setup.option.length",
            FT_UINT64, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_moqt_setup_option_integer,
          { "Setup Option Value", "moqt.setup.option.integer",
            FT_UINT64, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_moqt_setup_option_value,
          { "Setup Option Value", "moqt.setup.option.value",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_moqt_property_type_delta,
          { "Property Type Delta", "moqt.property.type_delta",
            FT_UINT64, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_moqt_property_type,
          { "Property Type", "moqt.property.type",
            FT_UINT64, BASE_HEX | BASE_VAL64_STRING,
            VALS64(moqt_property_type_vals), 0x0,
            NULL, HFILL }
        },
        { &hf_moqt_property_length,
          { "Property Length", "moqt.property.length",
            FT_UINT64, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_moqt_property_integer,
          { "Property Value", "moqt.property.integer",
            FT_UINT64, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_moqt_property_value,
          { "Property Value", "moqt.property.value",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_moqt_properties_length,
          { "Properties Length", "moqt.properties.length",
            FT_UINT64, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_moqt_group_id,
          { "Group ID", "moqt.group_id",
            FT_UINT64, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_moqt_group_id_delta,
          { "Group ID Delta", "moqt.group_id_delta",
            FT_UINT64, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_moqt_subgroup_id,
          { "Subgroup ID", "moqt.subgroup_id",
            FT_UINT64, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_moqt_object_id,
          { "Object ID", "moqt.object_id",
            FT_UINT64, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_moqt_object_id_delta,
          { "Object ID Delta", "moqt.object_id_delta",
            FT_UINT64, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_moqt_publisher_priority,
          { "Publisher Priority", "moqt.publisher_priority",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_moqt_object_status,
          { "Object Status", "moqt.object.status",
            FT_UINT64, BASE_HEX | BASE_VAL64_STRING,
            VALS64(moqt_object_status_vals), 0x0,
            NULL, HFILL }
        },
        { &hf_moqt_object_payload_length,
          { "Object Payload Length", "moqt.object.payload_length",
            FT_UINT64, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_moqt_object_payload,
          { "Object Payload", "moqt.object.payload",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_moqt_datagram_type,
          { "Datagram Type", "moqt.datagram.type",
            FT_UINT64, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_moqt_serialization_flags,
          { "Serialization Flags", "moqt.fetch.serialization_flags",
            FT_UINT64, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_moqt_subgroup_id_mode,
          { "Subgroup ID Mode", "moqt.subgroup_id_mode",
            FT_UINT8, BASE_DEC, VALS(moqt_subgroup_id_mode_vals), MOQT_SUBGROUP_ID_MODE,
            NULL, HFILL }
        },
        { &hf_moqt_fetch_subgroup_id_mode,
          { "Subgroup ID Mode", "moqt.fetch.flags.subgroup_id_mode",
            FT_UINT8, BASE_DEC, VALS(moqt_fetch_subgroup_id_mode_vals), MOQT_FETCH_SUBGROUP_ID_MODE,
            NULL, HFILL }
        },
        { &hf_moqt_fetch_group_id_delta_present,
          { "Group ID Delta Present", "moqt.fetch.flags.group_id_delta",
            FT_BOOLEAN, 64, NULL, MOQT_FETCH_GROUP_ID_DELTA,
            NULL, HFILL }
        },
        { &hf_moqt_fetch_object_id_delta_present,
          { "Object ID Delta Present", "moqt.fetch.flags.object_id_delta",
            FT_BOOLEAN, 64, NULL, MOQT_FETCH_OBJECT_ID_DELTA,
            NULL, HFILL }
        },
        { &hf_moqt_fetch_priority_present,
          { "Publisher Priority Present", "moqt.fetch.flags.priority",
            FT_BOOLEAN, 64, NULL, MOQT_FETCH_PRIORITY,
            NULL, HFILL }
        },
        { &hf_moqt_fetch_has_properties,
          { "Properties Present", "moqt.fetch.flags.properties",
            FT_BOOLEAN, 64, NULL, MOQT_FETCH_PROPERTIES,
            NULL, HFILL }
        },
        { &hf_moqt_subgroup_has_properties,
          { "Properties Present", "moqt.subgroup.flags.properties",
            FT_BOOLEAN, 64, NULL, MOQT_SUBGROUP_PROPERTIES,
            NULL, HFILL }
        },
        { &hf_moqt_subgroup_end_of_group,
          { "End of Group", "moqt.subgroup.flags.end_of_group",
            FT_BOOLEAN, 64, NULL, MOQT_SUBGROUP_END_OF_GROUP,
            NULL, HFILL }
        },
        { &hf_moqt_subgroup_default_priority,
          { "Default Priority", "moqt.subgroup.flags.default_priority",
            FT_BOOLEAN, 64, NULL, MOQT_SUBGROUP_DEFAULT_PRIORITY,
            NULL, HFILL }
        },
        { &hf_moqt_has_properties,
          { "Properties Present", "moqt.flags.properties",
            FT_BOOLEAN, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_moqt_end_of_group,
          { "End of Group", "moqt.flags.end_of_group",
            FT_BOOLEAN, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_moqt_zero_object_id,
          { "Object ID Is Zero", "moqt.flags.zero_object_id",
            FT_BOOLEAN, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_moqt_default_priority,
          { "Default Priority", "moqt.flags.default_priority",
            FT_BOOLEAN, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_moqt_status_present,
          { "Object Status Present", "moqt.flags.status",
            FT_BOOLEAN, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_moqt_first_object,
          { "Begins With First Object", "moqt.flags.first_object",
            FT_BOOLEAN, 64, NULL, MOQT_SUBGROUP_FIRST_OBJECT,
            NULL, HFILL }
        },
        { &hf_moqt_fetch_datagram_object,
          { "Datagram Forwarding Preference",
            "moqt.fetch.flags.datagram",
            FT_BOOLEAN, 64, NULL, MOQT_FETCH_DATAGRAM,
            NULL, HFILL }
        },
        { &hf_moqt_fetch_type,
          { "Fetch Type", "moqt.fetch.type",
            FT_UINT64, BASE_HEX | BASE_VAL64_STRING,
            VALS64(moqt_fetch_type_vals), 0x0,
            NULL, HFILL }
        },
        { &hf_moqt_end_of_track,
          { "End Of Track", "moqt.fetch.end_of_track",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_moqt_status_code,
          { "Status/Error Code", "moqt.status_code",
            FT_UINT64, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_moqt_stream_count,
          { "Stream Count", "moqt.stream_count",
            FT_UINT64, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_moqt_retry_interval,
          { "Retry Interval", "moqt.retry_interval",
            FT_UINT64, BASE_DEC, NULL, 0x0,
            "Retry interval in milliseconds, plus one", HFILL }
        },
        { &hf_moqt_reason_length,
          { "Reason Phrase Length", "moqt.reason.length",
            FT_UINT64, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_moqt_reason,
          { "Reason Phrase", "moqt.reason",
            FT_STRING, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_moqt_uri_length,
          { "URI Length", "moqt.uri.length",
            FT_UINT64, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_moqt_uri,
          { "URI", "moqt.uri",
            FT_STRING, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_moqt_timeout,
          { "Timeout", "moqt.timeout",
            FT_UINT64, BASE_DEC, NULL, 0x0,
            "Timeout in milliseconds", HFILL }
        },
        { &hf_moqt_filter_type,
          { "Subscription Filter Type", "moqt.filter.type",
            FT_UINT64, BASE_HEX | BASE_VAL64_STRING,
            VALS64(moqt_filter_type_vals), 0x0,
            NULL, HFILL }
        },
        { &hf_moqt_end_group_delta,
          { "End Group Delta", "moqt.filter.end_group_delta",
            FT_UINT64, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_moqt_alias_type,
          { "Alias Type", "moqt.token.alias_type",
            FT_UINT64, BASE_HEX | BASE_VAL64_STRING,
            VALS64(moqt_alias_type_vals), 0x0,
            NULL, HFILL }
        },
        { &hf_moqt_token_alias,
          { "Token Alias", "moqt.token.alias",
            FT_UINT64, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_moqt_token_type,
          { "Token Type", "moqt.token.type",
            FT_UINT64, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_moqt_token_value,
          { "Token Value", "moqt.token.value",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_moqt_padding,
          { "Padding", "moqt.padding",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_moqt_unparsed,
          { "Unparsed Data", "moqt.unparsed",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
    };

    static int *ett[] = {
        &ett_moqt,
        &ett_moqt_message,
        &ett_moqt_namespace,
        &ett_moqt_location,
        &ett_moqt_parameters,
        &ett_moqt_parameter,
        &ett_moqt_setup_options,
        &ett_moqt_setup_option,
        &ett_moqt_properties,
        &ett_moqt_property,
        &ett_moqt_stream_header,
        &ett_moqt_object,
        &ett_moqt_subgroup_type_flags,
        &ett_moqt_datagram_flags,
        &ett_moqt_serialization_flags,
    };

    static ei_register_info ei[] = {
        { &ei_moqt_truncated,
          { "moqt.truncated", PI_MALFORMED, PI_ERROR,
            "Truncated MOQT structure", EXPFILL }
        },
        { &ei_moqt_unknown_message,
          { "moqt.message.unknown", PI_PROTOCOL, PI_ERROR,
            "Unknown control message type", EXPFILL }
        },
        { &ei_moqt_unknown_stream,
          { "moqt.stream.unknown", PI_PROTOCOL, PI_ERROR,
            "Unknown unidirectional stream type", EXPFILL }
        },
        { &ei_moqt_invalid_type,
          { "moqt.type.invalid", PI_PROTOCOL, PI_ERROR,
            "Invalid type or field combination", EXPFILL }
        },
        { &ei_moqt_invalid_length,
          { "moqt.length.invalid", PI_MALFORMED, PI_ERROR,
            "Length exceeds containing structure", EXPFILL }
        },
        { &ei_moqt_unknown_parameter,
          { "moqt.parameter.unknown", PI_PROTOCOL, PI_ERROR,
            "Unknown message parameter", EXPFILL }
        },
        { &ei_moqt_namespace_too_large,
          { "moqt.namespace.too_large", PI_PROTOCOL, PI_ERROR,
            "Track namespace has more than 32 fields", EXPFILL }
        },
        { &ei_moqt_nonzero_padding,
          { "moqt.padding.nonzero", PI_MALFORMED, PI_ERROR,
            "Padding contains a non-zero byte", EXPFILL }
        },
        { &ei_moqt_stream_head_missing,
          { "moqt.stream_head_missing", PI_UNDECODED, PI_WARN,
            "Beginning of the QUIC stream was not captured", EXPFILL }
        },
        { &ei_moqt_empty_properties,
          { "moqt.properties.empty", PI_PROTOCOL, PI_ERROR,
            "Properties bit set with an empty Properties field", EXPFILL }
        },
        { &ei_moqt_object_id_overflow,
          { "moqt.object_id.overflow", PI_PROTOCOL, PI_ERROR,
            "Subgroup Object ID exceeds 2^64 - 1", EXPFILL }
        },
    };

    expert_module_t *expert_moqt;

    proto_moqt = proto_register_protocol(
        "Media over QUIC Transport", "MOQT", "moqt");
    for (unsigned i = 0; i < array_length(hf); i++) {
        if (hf[i].p_id == &hf_moqt_message_type) {
            hf[i].hfinfo.strings = VALS64(moqt_message_type_vals);
        } else if (hf[i].p_id == &hf_moqt_parameter_type) {
            hf[i].hfinfo.strings = VALS64(moqt_parameter_type_vals);
        }
    }
    proto_register_field_array(proto_moqt, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
    expert_moqt = expert_register_protocol(proto_moqt);
    expert_register_field_array(expert_moqt, ei, array_length(ei));

    moqt_handle = register_dissector("moqt", dissect_moqt, proto_moqt);
    moqt_datagram_handle = register_dissector(
        "moqt.datagram", dissect_moqt_datagram, proto_moqt);
}

void
proto_reg_handoff_moqt(void)
{
    dissector_add_string("quic.proto", moqt_draft18.alpn, moqt_handle);
    dissector_add_string("quic.proto.datagram", moqt_draft18.alpn,
                         moqt_datagram_handle);
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
