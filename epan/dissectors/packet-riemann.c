/**
 * packet-riemann.c
 * Routines for Riemann dissection
 * Copyright 2014, Sergey Avseyev <sergey.avseyev@gmail.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/* Riemann (http://riemann.io) aggregates events from servers and
 * applications with a powerful stream processing language.
 *
 * Protobuf structures layout:
 * https://github.com/riemann/riemann-java-client/blob/master/riemann-java-client/src/main/proto/riemann/proto.proto
 *
 *   message State {
 *     optional int64 time = 1;
 *     optional string state = 2;
 *     optional string service = 3;
 *     optional string host = 4;
 *     optional string description = 5;
 *     optional bool once = 6;
 *     repeated string tags = 7;
 *     optional float ttl = 8;
 *   }
 *
 *   message Event {
 *     optional int64 time = 1;
 *     optional string state = 2;
 *     optional string service = 3;
 *     optional string host = 4;
 *     optional string description = 5;
 *     repeated string tags = 7;
 *     optional float ttl = 8;
 *     repeated Attribute attributes = 9;
 *
 *     optional int64 time_micros = 10;
 *     optional sint64 metric_sint64 = 13;
 *     optional double metric_d = 14;
 *     optional float metric_f = 15;
 *   }
 *
 *   message Query {
 *     optional string string = 1;
 *   }
 *
 *   message Msg {
 *     optional bool ok = 2;
 *     optional string error = 3;
 *     repeated State states = 4;
 *     optional Query query = 5;
 *     repeated Event events = 6;
 *   }
 *
 *   message Attribute {
 *     required string key = 1;
 *     optional string value = 2;
 *   }
 */

#include "config.h"

#include <epan/packet.h>
#include <epan/expert.h>
#include "packet-tcp.h"

void proto_reg_handoff_riemann(void);
void proto_register_riemann(void);

static dissector_handle_t riemann_udp_handle, riemann_tcp_handle;

static int proto_riemann;
static int hf_riemann_msg_ok;
static int hf_riemann_msg_error;
static int hf_riemann_attribute;
static int hf_riemann_attribute_key;
static int hf_riemann_attribute_value;
static int hf_riemann_query;
static int hf_riemann_query_string;
static int hf_riemann_event;
static int hf_riemann_event_state;
static int hf_riemann_event_service;
static int hf_riemann_event_host;
static int hf_riemann_event_description;
static int hf_riemann_event_tag;
static int hf_riemann_event_ttl;
static int hf_riemann_event_time;
static int hf_riemann_event_metric_d;
static int hf_riemann_event_metric_f;
static int hf_riemann_event_time_micros;
static int hf_riemann_event_metric_sint64;
static int hf_riemann_state;
static int hf_riemann_state_service;
static int hf_riemann_state_host;
static int hf_riemann_state_description;
static int hf_riemann_state_tag;
static int hf_riemann_state_ttl;
static int hf_riemann_state_time;
static int hf_riemann_state_state;
static int hf_riemann_state_once;

static int ett_riemann;
static int ett_query;
static int ett_event;
static int ett_attribute;
static int ett_state;

#define RIEMANN_MIN_LENGTH 16
#define RIEMANN_MIN_NEEDED_FOR_HEURISTICS 10

/* field numbers. see protocol definition above */
#define RIEMANN_FN_MSG_OK 2
#define RIEMANN_FN_MSG_ERROR 3
#define RIEMANN_FN_MSG_STATES 4
#define RIEMANN_FN_MSG_QUERY 5
#define RIEMANN_FN_MSG_EVENTS 6

#define RIEMANN_FN_EVENT_TIME 1
#define RIEMANN_FN_EVENT_STATE 2
#define RIEMANN_FN_EVENT_SERVICE 3
#define RIEMANN_FN_EVENT_HOST 4
#define RIEMANN_FN_EVENT_DESCRIPTION 5
#define RIEMANN_FN_EVENT_TAGS 7
#define RIEMANN_FN_EVENT_TTL 8
#define RIEMANN_FN_EVENT_ATTRIBUTES 9
#define RIEMANN_FN_EVENT_TIME_MICROS 10
#define RIEMANN_FN_EVENT_METRIC_SINT64 13
#define RIEMANN_FN_EVENT_METRIC_D 14
#define RIEMANN_FN_EVENT_METRIC_F 15

#define RIEMANN_FN_ATTRIBUTE_KEY 1
#define RIEMANN_FN_ATTRIBUTE_VALUE 2

#define RIEMANN_FN_STATE_TIME 1
#define RIEMANN_FN_STATE_STATE 2
#define RIEMANN_FN_STATE_SERVICE 3
#define RIEMANN_FN_STATE_HOST 4
#define RIEMANN_FN_STATE_DESCRIPTION 5
#define RIEMANN_FN_STATE_ONCE 6
#define RIEMANN_FN_STATE_TAGS 7
#define RIEMANN_FN_STATE_TTL 8

#define RIEMANN_FN_QUERY_STRING 1

/* type codes. see protocol definition above */
#define RIEMANN_WIRE_INTEGER 0
#define RIEMANN_WIRE_DOUBLE 1
#define RIEMANN_WIRE_BYTES 2
#define RIEMANN_WIRE_FLOAT 5

static expert_field ei_error_unknown_wire_tag;
static expert_field ei_error_unknown_field_number;
static expert_field ei_error_insufficient_data;

static void
riemann_verify_wire_format(uint64_t field_number, const char *field_name, int expected, int actual,
                           packet_info *pinfo, proto_item *pi)
{
    if (expected != actual) {
        const char *wire_name;

        switch (expected) {
        case RIEMANN_WIRE_INTEGER:
            wire_name = "integer";
            break;
        case RIEMANN_WIRE_BYTES:
            wire_name = "bytes/string";
            break;
        case RIEMANN_WIRE_FLOAT:
            wire_name = "float";
            break;
        case RIEMANN_WIRE_DOUBLE:
            wire_name = "double";
            break;
        default:
            wire_name = "unknown (check packet-riemann.c)";
            break;
        }
        expert_add_info_format(pinfo, pi, &ei_error_unknown_wire_tag,
                               "Expected %s (%d) field to be an %s (%d), but it is %d",
                               field_name, (int)field_number, wire_name, expected, actual);
    }
}

#define VERIFY_WIRE_FORMAT(field_name, expected) \
    riemann_verify_wire_format(fn, field_name, expected, wire, pinfo, pi)

#define UNKNOWN_FIELD_NUMBER_FOR(message_name) \
    expert_add_info_format(pinfo, pi, &ei_error_unknown_field_number, \
                           "Unknown field number %d for " message_name " (wire format %d)", \
                           (int)fn, (int)wire);

#define VERIFY_SIZE_FOR(message_name) \
    if (size < 0) { \
       expert_add_info_format(pinfo, pi, &ei_error_insufficient_data, \
                              "Insufficient data for " message_name " (%d bytes needed)", \
                              (int)size * -1); \
    }

static uint64_t
riemann_get_guint64(tvbuff_t *tvb, unsigned offset, unsigned *len)
{
    uint64_t num   = 0;
    unsigned   shift = 0;
    *len = 0;
    while (1) {
        uint8_t b;
        if (shift >= 64) {
            return 0;
        }
        b = tvb_get_uint8(tvb, offset++);
        num |= ((uint64_t)(b & 0x7f) << shift);
        shift += 7;
        (*len)++;
        if ((b & 0x80) == 0) {
            return num;
        }
    }
    return 0;
}

static uint8_t *
riemann_get_string(wmem_allocator_t *scope, tvbuff_t *tvb, int offset)
{
    uint64_t size;
    unsigned   len = 0;

    size = riemann_get_guint64(tvb, offset, &len);
    offset += len;
    return tvb_get_string_enc(scope, tvb, offset, (int)size, ENC_ASCII);
}

static unsigned
riemann_dissect_int64(proto_tree *riemann_tree, tvbuff_t *tvb, unsigned offset, int hf_index)
{
    uint64_t num;
    unsigned   len = 0;

    num = riemann_get_guint64(tvb, offset, &len);
    proto_tree_add_int64(riemann_tree, hf_index, tvb, offset, len, num);
    return len;
}

static unsigned
riemann_dissect_sint64(proto_tree *riemann_tree, tvbuff_t *tvb, unsigned offset, int hf_index)
{
    uint64_t num;
    int64_t snum;
    unsigned len = 0;

    num = riemann_get_guint64(tvb, offset, &len);
    /* zigzag decoding */
    if (num & 1) {
        snum = -((int64_t)(num >> 1)) - 1;
    } else {
        snum = (int64_t)(num >> 1);
    }

    proto_tree_add_int64(riemann_tree, hf_index, tvb, offset, len, snum);
    return len;
}

static unsigned
riemann_dissect_string(proto_tree *riemann_tree, tvbuff_t *tvb, unsigned offset, int hf_index)
{
    uint64_t size;
    unsigned   len = 0, orig_offset = offset;

    size = riemann_get_guint64(tvb, offset, &len);
    offset += len;
    proto_tree_add_item(riemann_tree, hf_index, tvb, offset, (int)size, ENC_ASCII);
    offset += (int)size;

    return offset - orig_offset;
}

static unsigned
riemann_dissect_attribute(packet_info *pinfo, proto_tree *riemann_tree,
                          tvbuff_t *tvb, unsigned offset)
{
    uint64_t    tag, fn;
    int64_t     size;
    uint8_t     wire;
    unsigned    len         = 0;
    unsigned    orig_offset = offset;
    proto_item *pi;
    proto_tree *attribute_tree;

    size = (int64_t)riemann_get_guint64(tvb, offset, &len);
    pi = proto_tree_add_item(riemann_tree, hf_riemann_attribute, tvb, (int)offset, (int)(size + len), ENC_NA);
    attribute_tree = proto_item_add_subtree(pi, ett_attribute);
    offset += len;

    while (size > 0) {
        tag  = riemann_get_guint64(tvb, offset, &len);
        fn   = tag >> 3;
        wire = tag & 0x7;
        offset += len;
        size   -= len;
        switch (fn) {
        case RIEMANN_FN_ATTRIBUTE_KEY:
            VERIFY_WIRE_FORMAT("Attribute.key", RIEMANN_WIRE_BYTES);
            len = riemann_dissect_string(attribute_tree, tvb, offset, hf_riemann_attribute_key);
            break;
        case RIEMANN_FN_ATTRIBUTE_VALUE:
            VERIFY_WIRE_FORMAT("Attribute.value", RIEMANN_WIRE_BYTES);
            len = riemann_dissect_string(attribute_tree, tvb, offset, hf_riemann_attribute_value);
            break;
        default:
            len = 0;
            UNKNOWN_FIELD_NUMBER_FOR("Attribute");
        }
        offset += len;
        size   -= len;
    }
    VERIFY_SIZE_FOR("Attribute");

    return offset - orig_offset;
}

static unsigned
riemann_dissect_query(packet_info *pinfo, proto_tree *riemann_tree,
                      tvbuff_t *tvb, unsigned offset)
{
    uint64_t    tag, fn;
    int64_t     size;
    uint8_t     wire;
    unsigned    orig_offset = offset, len = 0;
    proto_item *pi;
    proto_tree *query_tree;

    size = (int64_t)riemann_get_guint64(tvb, offset, &len);
    pi = proto_tree_add_item(riemann_tree, hf_riemann_query, tvb, (int)offset, (int)(size + len), ENC_NA);
    query_tree = proto_item_add_subtree(pi, ett_query);
    offset += len;

    while (size > 0) {
        tag  = riemann_get_guint64(tvb, offset, &len);
        fn   = tag >> 3;
        wire = tag & 0x7;
        offset += len;
        size   -= len;
        switch (fn) {
        case RIEMANN_FN_QUERY_STRING:
            VERIFY_WIRE_FORMAT("Query.string", RIEMANN_WIRE_BYTES);
            col_append_str(pinfo->cinfo, COL_INFO, riemann_get_string(pinfo->pool, tvb, offset));
            len = riemann_dissect_string(query_tree, tvb, offset, hf_riemann_query_string);
            break;
        default:
            len = 0;
            UNKNOWN_FIELD_NUMBER_FOR("Query");
        }
        offset += len;
        size   -= len;
    }
    VERIFY_SIZE_FOR("Query");

    return offset - orig_offset;
}

static unsigned
riemann_dissect_event(packet_info *pinfo, proto_tree *riemann_tree,
                      tvbuff_t *tvb, unsigned offset)
{
    unsigned    orig_offset = offset, len = 0;
    uint64_t    tag, fn;
    int64_t     size;
    uint8_t     wire;
    proto_item *pi;
    proto_tree *event_tree;
    bool        need_comma  = false;

    size = riemann_get_guint64(tvb, offset, &len);
    pi = proto_tree_add_item(riemann_tree, hf_riemann_event, tvb, (int)offset, (int)(size + len), ENC_NA);
    event_tree = proto_item_add_subtree(pi, ett_event);
    offset += len;

    while (size > 0) {
        const char *comma = need_comma ? ", " : "";
        tag  = riemann_get_guint64(tvb, offset, &len);
        fn   = tag >> 3;
        wire = tag & 0x7;
        offset += len;
        size   -= len;
        switch (fn) {
        case RIEMANN_FN_EVENT_TIME:
            VERIFY_WIRE_FORMAT("Event.time", RIEMANN_WIRE_INTEGER);
            len = riemann_dissect_int64(event_tree, tvb, offset, hf_riemann_event_time);
            break;
        case RIEMANN_FN_EVENT_STATE:
            VERIFY_WIRE_FORMAT("Event.state", RIEMANN_WIRE_BYTES);
            len = riemann_dissect_string(event_tree, tvb, offset, hf_riemann_event_state);
            break;
        case RIEMANN_FN_EVENT_SERVICE:
            VERIFY_WIRE_FORMAT("Event.service", RIEMANN_WIRE_BYTES);
            col_append_fstr(pinfo->cinfo, COL_INFO, "%s%s", comma, riemann_get_string(pinfo->pool, tvb, offset));
            len = riemann_dissect_string(event_tree, tvb, offset, hf_riemann_event_service);
            need_comma = true;
            break;
        case RIEMANN_FN_EVENT_HOST:
            VERIFY_WIRE_FORMAT("Event.host", RIEMANN_WIRE_BYTES);
            col_append_fstr(pinfo->cinfo, COL_INFO, "%s%s", comma, riemann_get_string(pinfo->pool, tvb, offset));
            len = riemann_dissect_string(event_tree, tvb, offset, hf_riemann_event_host);
            need_comma = true;
            break;
        case RIEMANN_FN_EVENT_DESCRIPTION:
            VERIFY_WIRE_FORMAT("Event.description", RIEMANN_WIRE_BYTES);
            len = riemann_dissect_string(event_tree, tvb, offset, hf_riemann_event_description);
            break;
        case RIEMANN_FN_EVENT_TAGS:
            VERIFY_WIRE_FORMAT("Event.tags", RIEMANN_WIRE_BYTES);
            len = riemann_dissect_string(event_tree, tvb, offset, hf_riemann_event_tag);
            break;
        case RIEMANN_FN_EVENT_TTL:
            VERIFY_WIRE_FORMAT("Event.ttl", RIEMANN_WIRE_FLOAT);
            proto_tree_add_item(event_tree, hf_riemann_event_ttl, tvb, offset, 4, ENC_LITTLE_ENDIAN);
            len = 4;
            break;
        case RIEMANN_FN_EVENT_ATTRIBUTES:
            VERIFY_WIRE_FORMAT("Event.attributes", RIEMANN_WIRE_BYTES);
            len = riemann_dissect_attribute(pinfo, event_tree, tvb, offset);
            break;
        case RIEMANN_FN_EVENT_TIME_MICROS:
            VERIFY_WIRE_FORMAT("Event.time_micros", RIEMANN_WIRE_INTEGER);
            len = riemann_dissect_int64(event_tree, tvb, offset, hf_riemann_event_time_micros);
            break;
        case RIEMANN_FN_EVENT_METRIC_SINT64:
            VERIFY_WIRE_FORMAT("Event.metric_sint64", RIEMANN_WIRE_INTEGER);
            len = riemann_dissect_sint64(event_tree, tvb, offset, hf_riemann_event_metric_sint64);
            break;
        case RIEMANN_FN_EVENT_METRIC_D:
            VERIFY_WIRE_FORMAT("Event.metric_d", RIEMANN_WIRE_DOUBLE);
            proto_tree_add_item(event_tree, hf_riemann_event_metric_d, tvb, offset, 8, ENC_LITTLE_ENDIAN);
            len = 8;
            break;
        case RIEMANN_FN_EVENT_METRIC_F:
            VERIFY_WIRE_FORMAT("Event.metric_f", RIEMANN_WIRE_FLOAT);
            proto_tree_add_item(event_tree, hf_riemann_event_metric_f, tvb, offset, 4, ENC_LITTLE_ENDIAN);
            len = 4;
            break;
        default:
            len = 0;
            UNKNOWN_FIELD_NUMBER_FOR("Event");
        }
        offset += len;
        size   -= len;
    }
    col_append_str(pinfo->cinfo, COL_INFO, "; ");
    VERIFY_SIZE_FOR("Event");

    return offset - orig_offset;
}

static unsigned
riemann_dissect_state(packet_info *pinfo, proto_tree *riemann_tree,
                      tvbuff_t *tvb, unsigned offset)
{
    unsigned    orig_offset = offset, len = 0;
    uint64_t    tag, fn;
    int64_t     size;
    uint8_t     wire;
    proto_item *pi;
    proto_tree *state_tree;
    bool        need_comma  = false;

    size = riemann_get_guint64(tvb, offset, &len);
    pi   = proto_tree_add_item(riemann_tree, hf_riemann_state, tvb, offset, (int)(size + len), ENC_NA);
    state_tree = proto_item_add_subtree(pi, ett_state);
    offset += len;

    while (size > 0) {
        const char *comma = need_comma ? ", " : "";
        tag  = riemann_get_guint64(tvb, offset, &len);
        fn   = tag >> 3;
        wire = tag & 0x7;
        offset += len;
        size   -= len;
        switch (fn) {
        case RIEMANN_FN_STATE_TIME:
            VERIFY_WIRE_FORMAT("State.time", RIEMANN_WIRE_INTEGER);
            len = riemann_dissect_int64(state_tree, tvb, offset, hf_riemann_state_time);
            break;
        case RIEMANN_FN_STATE_SERVICE:
            VERIFY_WIRE_FORMAT("State.service", RIEMANN_WIRE_BYTES);
            col_append_fstr(pinfo->cinfo, COL_INFO, "%s%s", comma, riemann_get_string(pinfo->pool, tvb, offset));
            len = riemann_dissect_string(state_tree, tvb, offset, hf_riemann_state_service);
            need_comma = true;
            break;
        case RIEMANN_FN_STATE_HOST:
            VERIFY_WIRE_FORMAT("State.host", RIEMANN_WIRE_BYTES);
            col_append_fstr(pinfo->cinfo, COL_INFO, "%s%s", comma, riemann_get_string(pinfo->pool, tvb, offset));
            len = riemann_dissect_string(state_tree, tvb, offset, hf_riemann_state_host);
            need_comma = true;
            break;
        case RIEMANN_FN_STATE_DESCRIPTION:
            VERIFY_WIRE_FORMAT("State.description", RIEMANN_WIRE_BYTES);
            len = riemann_dissect_string(state_tree, tvb, offset, hf_riemann_state_description);
            break;
        case RIEMANN_FN_STATE_TAGS:
            VERIFY_WIRE_FORMAT("State.tags", RIEMANN_WIRE_BYTES);
            len = riemann_dissect_string(state_tree, tvb, offset, hf_riemann_state_tag);
            break;
        case RIEMANN_FN_STATE_TTL:
            VERIFY_WIRE_FORMAT("State.ttl", RIEMANN_WIRE_FLOAT);
            proto_tree_add_item(state_tree, hf_riemann_state_ttl, tvb, offset, 4, ENC_LITTLE_ENDIAN);
            len = 4;
            break;
        case RIEMANN_FN_STATE_STATE:
            VERIFY_WIRE_FORMAT("State.state", RIEMANN_WIRE_BYTES);
            len = riemann_dissect_string(state_tree, tvb, offset, hf_riemann_state_state);
            break;
        case RIEMANN_FN_STATE_ONCE:
            VERIFY_WIRE_FORMAT("State.once", RIEMANN_WIRE_INTEGER);
            proto_tree_add_item(state_tree, hf_riemann_state_once, tvb, offset, 1, ENC_NA);
            len = 1;
            break;
        default:
            len = 0;
            UNKNOWN_FIELD_NUMBER_FOR("State");
        }
        offset += len;
        size   -= len;
    }
    col_append_str(pinfo->cinfo, COL_INFO, "; ");
    VERIFY_SIZE_FOR("State");

    return offset - orig_offset;
}

static unsigned
riemann_dissect_msg(packet_info *pinfo, proto_item *pi, proto_tree *riemann_tree,
                    tvbuff_t *tvb, unsigned offset)
{
    uint64_t tag, fn;
    int64_t  size = (int64_t)tvb_reported_length_remaining(tvb, offset);
    uint8_t  wire;
    unsigned len, orig_offset = offset;
    bool cinfo_set = false;

    while (size > 0) {
        tag  = riemann_get_guint64(tvb, offset, &len);
        fn   = tag >> 3;
        wire = tag & 0x7;
        offset += len;
        size   -= len;

        switch (fn) {
        case RIEMANN_FN_MSG_OK:
            VERIFY_WIRE_FORMAT("Msg.ok", RIEMANN_WIRE_INTEGER);
            proto_tree_add_item(riemann_tree, hf_riemann_msg_ok, tvb, offset, 1, ENC_NA);
            len = 1;
            break;
        case RIEMANN_FN_MSG_ERROR:
            VERIFY_WIRE_FORMAT("Msg.error", RIEMANN_WIRE_BYTES);
            len = riemann_dissect_string(riemann_tree, tvb, offset, hf_riemann_msg_error);
            break;
        case RIEMANN_FN_MSG_QUERY:
            VERIFY_WIRE_FORMAT("Msg.query", RIEMANN_WIRE_BYTES);
            if (!cinfo_set) {
                col_set_str(pinfo->cinfo, COL_INFO, "Query: ");
                cinfo_set = true;
            }
            len = riemann_dissect_query(pinfo, riemann_tree, tvb, offset);
            break;
        case RIEMANN_FN_MSG_EVENTS:
            VERIFY_WIRE_FORMAT("Msg.events", RIEMANN_WIRE_BYTES);
            if (!cinfo_set) {
                col_set_str(pinfo->cinfo, COL_INFO, "Event: ");
                cinfo_set = true;
            }
            len = riemann_dissect_event(pinfo, riemann_tree, tvb, offset);
            break;
        case RIEMANN_FN_MSG_STATES:
            VERIFY_WIRE_FORMAT("Msg.states", RIEMANN_WIRE_BYTES);
            if (!cinfo_set) {
                col_set_str(pinfo->cinfo, COL_INFO, "State: ");
                cinfo_set = true;
            }
            len = riemann_dissect_state(pinfo, riemann_tree, tvb, offset);
            break;
        default:
            len = 0;
            UNKNOWN_FIELD_NUMBER_FOR("Msg");
        }
        offset += len;
        size -= len;
    }
    VERIFY_SIZE_FOR("Msg");

    return offset - orig_offset;
}

static bool
is_riemann(tvbuff_t *tvb, unsigned offset)
{
    uint32_t reported_length = tvb_reported_length_remaining(tvb, offset);
    uint32_t captured_length = tvb_captured_length_remaining(tvb, offset);
    uint64_t tag, field_number, wire_format;
    unsigned len;

    if ((reported_length < RIEMANN_MIN_LENGTH) ||
        (captured_length < RIEMANN_MIN_NEEDED_FOR_HEURISTICS)) {
        return false;
    }
    tag = riemann_get_guint64(tvb, offset, &len);
    field_number = tag >> 3;
    wire_format  = tag & 0x7;
    if ((field_number == RIEMANN_FN_MSG_OK     && wire_format == RIEMANN_WIRE_INTEGER) ||
        (field_number == RIEMANN_FN_MSG_ERROR  && wire_format == RIEMANN_WIRE_BYTES)   ||
        (field_number == RIEMANN_FN_MSG_QUERY  && wire_format == RIEMANN_WIRE_BYTES)   ||
        (field_number == RIEMANN_FN_MSG_EVENTS && wire_format == RIEMANN_WIRE_BYTES)   ||
        (field_number == RIEMANN_FN_MSG_STATES && wire_format == RIEMANN_WIRE_BYTES)) {
        return true;
    }
    return false;
}

static int
dissect_riemann(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    proto_item *pi;
    proto_tree *riemann_tree;

    if (!is_riemann(tvb, offset))
        return 0;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "riemann");
    col_clear(pinfo->cinfo, COL_INFO);

    pi = proto_tree_add_item(tree, proto_riemann, tvb, offset, -1, ENC_NA);
    riemann_tree = proto_item_add_subtree(pi, ett_riemann);

    return riemann_dissect_msg(pinfo, pi, riemann_tree, tvb, offset);
}

static int
dissect_riemann_udp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    return dissect_riemann(tvb, pinfo, tree, 0);
}

static int
dissect_riemann_tcp_pdu(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    return dissect_riemann(tvb, pinfo, tree, 4);
}

static unsigned
get_riemann_tcp_pdu_len(packet_info *pinfo _U_, tvbuff_t *tvb,
                        int offset, void *data _U_)
{
    return (tvb_get_ntohl(tvb, offset) + 4);
}

static int
dissect_riemann_tcp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
    tcp_dissect_pdus(tvb, pinfo, tree, true, 4, get_riemann_tcp_pdu_len, dissect_riemann_tcp_pdu, data);

    return tvb_captured_length(tvb);
}

void
proto_register_riemann(void)
{
    expert_module_t *riemann_expert_module;

    static hf_register_info hf[] = {
        { &hf_riemann_msg_ok,
          { "ok", "riemann.msg.ok",
            FT_BOOLEAN, BASE_NONE, NULL, 0, NULL, HFILL }
        },
        { &hf_riemann_msg_error,
          { "error", "riemann.msg.error",
            FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }
        },
        { &hf_riemann_attribute,
          { "attribute", "riemann.attribute",
            FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL }
        },
        { &hf_riemann_attribute_key,
          { "key", "riemann.attribute.key",
            FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }
        },
        { &hf_riemann_attribute_value,
          { "value", "riemann.attribute.value",
            FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }
        },
        { &hf_riemann_query,
          { "query", "riemann.query",
            FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL }
        },
        { &hf_riemann_query_string,
          { "string", "riemann.query.string",
            FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }
        },
        { &hf_riemann_event,
          { "event", "riemann.event",
            FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL }
        },
        { &hf_riemann_event_state,
          { "state", "riemann.event.state",
            FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }
        },
        { &hf_riemann_event_service,
          { "service", "riemann.event.service",
            FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }
        },
        { &hf_riemann_event_host,
          { "host", "riemann.event.host",
            FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }
        },
        { &hf_riemann_event_description,
          { "description", "riemann.event.description",
            FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }
        },
        { &hf_riemann_event_tag,
          { "tag", "riemann.event.tag",
            FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }
        },
        { &hf_riemann_event_time,
          { "time", "riemann.event.time",
            FT_INT64, BASE_DEC, NULL, 0, NULL, HFILL }
        },
        { &hf_riemann_event_ttl,
          { "ttl", "riemann.event.ttl",
            FT_FLOAT, BASE_NONE, NULL, 0, NULL, HFILL }
        },
        { &hf_riemann_event_metric_d,
          { "metric_d", "riemann.event.metric_d",
            FT_DOUBLE, BASE_NONE, NULL, 0, NULL, HFILL }
        },
        { &hf_riemann_event_metric_f,
          { "metric_f", "riemann.event.metric_f",
            FT_FLOAT, BASE_NONE, NULL, 0, NULL, HFILL }
        },
        { &hf_riemann_event_time_micros,
          { "time_micros", "riemann.event.time_micros",
            FT_INT64, BASE_DEC, NULL, 0, NULL, HFILL }
        },
        { &hf_riemann_event_metric_sint64,
          { "metric_sint64", "riemann.event.metric_sint64",
            FT_INT64, BASE_DEC, NULL, 0, NULL, HFILL }
        },
        { &hf_riemann_state,
          { "state", "riemann.state",
            FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL }
        },
        { &hf_riemann_state_service,
          { "service", "riemann.state.service",
            FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }
        },
        { &hf_riemann_state_host,
          { "host", "riemann.state.host",
            FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }
        },
        { &hf_riemann_state_description,
          { "description", "riemann.state.description",
            FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }
        },
        { &hf_riemann_state_tag,
          { "tag", "riemann.state.tag",
            FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }
        },
        { &hf_riemann_state_time,
          { "time", "riemann.state.time",
            FT_INT64, BASE_DEC, NULL, 0, NULL, HFILL }
        },
        { &hf_riemann_state_ttl,
          { "ttl", "riemann.state.ttl",
            FT_FLOAT, BASE_NONE, NULL, 0, NULL, HFILL }
        },
        { &hf_riemann_state_state,
          { "state", "riemann.state.state",
            FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }
        },
        { &hf_riemann_state_once,
          { "once", "riemann.state.once",
            FT_BOOLEAN, BASE_NONE, NULL, 0, NULL, HFILL }
        }
    };

    static ei_register_info ei[] = {
        { &ei_error_unknown_wire_tag,
          { "riemann.unknown_wire_tag", PI_MALFORMED, PI_ERROR,
            "Invalid format type", EXPFILL }},
        { &ei_error_unknown_field_number,
          { "riemann.unknown_field_number", PI_MALFORMED, PI_ERROR,
            "Unknown field number", EXPFILL }},
        { &ei_error_insufficient_data,
          { "riemann.insufficient_data", PI_MALFORMED, PI_ERROR,
            "Insufficient data", EXPFILL }}
    };

    static int *ett[] = {
        &ett_riemann,
        &ett_query,
        &ett_event,
        &ett_attribute,
        &ett_state
    };

    proto_riemann = proto_register_protocol("Riemann", "Riemann", "riemann");
    riemann_expert_module = expert_register_protocol(proto_riemann);
    expert_register_field_array(riemann_expert_module, ei, array_length(ei));

    proto_register_field_array(proto_riemann, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    riemann_udp_handle = register_dissector("riemann.udp", dissect_riemann_udp, proto_riemann);
    riemann_tcp_handle = register_dissector("riemann.tcp", dissect_riemann_tcp, proto_riemann);
}

void
proto_reg_handoff_riemann(void)
{
    dissector_add_for_decode_as_with_preference("tcp.port", riemann_tcp_handle);
    dissector_add_for_decode_as_with_preference("udp.port", riemann_udp_handle);
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
