/* packet-kafka.c
 * Routines for Kafka Protocol dissection (version 0.8 and later)
 * Copyright 2013, Evan Huus <eapache@gmail.com>
 *
 * https://cwiki.apache.org/confluence/display/KAFKA/A+Guide+To+The+Kafka+Protocol
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include "config.h"

#include <glib.h>

#include <epan/dissectors/packet-tcp.h>
#include <epan/conversation.h>
#include <epan/packet.h>
#include <epan/prefs.h>
#include <epan/wmem/wmem.h>

void proto_register_kafka(void);
void proto_reg_handoff_kafka(void);

static int proto_kafka                  = -1;
static int hf_kafka_len                 = -1;
static int hf_kafka_request_api_key     = -1;
static int hf_kafka_response_api_key    = -1;
static int hf_kafka_request_api_version = -1;
static int hf_kafka_correlation_id      = -1;
static int hf_kafka_client_id           = -1;
static int hf_kafka_string_len          = -1;
static int hf_kafka_bytes_len           = -1;
static int hf_kafka_array_count         = -1;
static int hf_kafka_required_acks       = -1;
static int hf_kafka_timeout             = -1;
static int hf_kafka_topic_name          = -1;
static int hf_kafka_partition_id        = -1;
static int hf_kafka_replica             = -1;
static int hf_kafka_isr                 = -1;
static int hf_kafka_partition_leader    = -1;
static int hf_kafka_message_set_size    = -1;
static int hf_kafka_message_size        = -1;
static int hf_kafka_message_crc         = -1;
static int hf_kafka_message_magic       = -1;
static int hf_kafka_message_codec       = -1;
static int hf_kafka_message_key         = -1;
static int hf_kafka_message_value       = -1;
static int hf_kafka_request_frame       = -1;
static int hf_kafka_response_frame      = -1;
static int hf_kafka_consumer_group      = -1;
static int hf_kafka_offset              = -1;
static int hf_kafka_metadata            = -1;
static int hf_kafka_error               = -1;
static int hf_kafka_broker_nodeid       = -1;
static int hf_kafka_broker_host         = -1;
static int hf_kafka_broker_port         = -1;
static int hf_kafka_min_bytes           = -1;
static int hf_kafka_max_bytes           = -1;
static int hf_kafka_max_wait_time       = -1;

static gint ett_kafka                    = -1;
static gint ett_kafka_message            = -1;
static gint ett_kafka_message_set        = -1;
static gint ett_kafka_metadata_replicas  = -1;
static gint ett_kafka_metadata_isr       = -1;
static gint ett_kafka_metadata_broker    = -1;
static gint ett_kafka_metadata_brokers   = -1;
static gint ett_kafka_metadata_topics    = -1;
static gint ett_kafka_request_topic      = -1;
static gint ett_kafka_request_partition  = -1;
static gint ett_kafka_response_topic     = -1;
static gint ett_kafka_response_partition = -1;

static guint kafka_port = 0;

#define KAFKA_PRODUCE            0
#define KAFKA_FETCH              1
#define KAFKA_OFFSET             2
#define KAFKA_METADATA           3
/* 4-7 are "non-user facing control APIs" and are not documented */
#define KAFKA_OFFSET_COMMIT      8
#define KAFKA_OFFSET_FETCH       9
#define KAFKA_CONSUMER_METADATA 10
static const value_string kafka_apis[] = {
    { KAFKA_PRODUCE,           "Produce"             },
    { KAFKA_FETCH,             "Fetch"               },
    { KAFKA_OFFSET,            "Offset"              },
    { KAFKA_METADATA,          "Metadata"            },
    { KAFKA_OFFSET_COMMIT,     "Offset Commit"       },
    { KAFKA_OFFSET_FETCH,      "Offset Fetch"        },
    { KAFKA_CONSUMER_METADATA, "Consumer Metadata"   },
    { 0, NULL }
};

static const value_string kafka_errors[] = {
    { -1, "Unexpected Server Error" },
    { 0, "No Error" },
    { 1, "Offset Out Of Range" },
    { 2, "Invalid Message" },
    { 3, "Unknown Topic or Partition" },
    { 4, "Invalid Message Size" },
    { 5, "Leader Not Available" },
    { 6, "Not Leader For Partition" },
    { 7, "Request Timed Out" },
    { 8, "Broker Not Available" },
    { 10, "Message Size Too Large" },
    { 11, "Stale Controller Epoch Code" },
    { 12, "Offset Metadata Too Large" },
    { 14, "Offsets Load In Progress" },
    { 15, "Consumer Coordinator Not Available" },
    { 16, "Not Coordinator For Consumer" },
    { 0, NULL }
};

#define KAFKA_COMPRESSION_NONE   0
#define KAFKA_COMPRESSION_GZIP   1
#define KAFKA_COMPRESSION_SNAPPY 2
static const value_string kafka_codecs[] = {
    { KAFKA_COMPRESSION_NONE,   "None"   },
    { KAFKA_COMPRESSION_GZIP,   "Gzip"   },
    { KAFKA_COMPRESSION_SNAPPY, "Snappy" },
    { 0, NULL }
};

typedef struct _kafka_query_response_t {
    gint16   api_key;
    guint32  request_frame;
    guint32  response_frame;
    gboolean response_found;
} kafka_query_response_t;

static int
dissect_kafka_message(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int start_offset);
static int
dissect_kafka_message_set(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int start_offset);

/* HELPERS */

static guint
get_kafka_pdu_len(packet_info *pinfo _U_, tvbuff_t *tvb, int offset)
{
    return 4 + tvb_get_ntohl(tvb, offset);
}

static int
dissect_kafka_array(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, int offset, int(*func)(tvbuff_t*, packet_info*, proto_tree*, int))
{
    gint32 count, i;

    count = (gint32) tvb_get_ntohl(tvb, offset);
    proto_tree_add_item(tree, hf_kafka_array_count, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;

    for (i=0; i<count; i++) {
        offset = func(tvb, pinfo, tree, offset);
    }

    return offset;
}

static int
dissect_kafka_string(proto_tree *tree, int hf_item, tvbuff_t *tvb, packet_info *pinfo _U_, int offset)
{
    gint16 len;

    len = (gint16) tvb_get_ntohs(tvb, offset);
    proto_tree_add_item(tree, hf_kafka_string_len, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    if (len < -1) {
        /* TODO expert info */
    }
    else if (len == -1) {
        proto_tree_add_string(tree, hf_item, tvb, offset, 0, NULL);
    }
    else {
        proto_tree_add_item(tree, hf_item, tvb, offset, len, ENC_NA|ENC_ASCII);
        offset += len;
    }

    return offset;
}

static int
dissect_kafka_bytes(proto_tree *tree, int hf_item, tvbuff_t *tvb, packet_info *pinfo _U_, int offset)
{
    gint32 len;

    len = (gint32) tvb_get_ntohl(tvb, offset);
    proto_tree_add_item(tree, hf_kafka_bytes_len, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;

    if (len < -1) {
        /* TODO expert info */
    }
    else if (len == -1) {
        proto_tree_add_bytes(tree, hf_item, tvb, offset, 0, NULL);
    }
    else {
        proto_tree_add_item(tree, hf_item, tvb, offset, len, ENC_NA);
        offset += len;
    }

    return offset;
}

static tvbuff_t *
kafka_get_bytes(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo _U_, int offset)
{
    gint32 len;

    len = (gint32) tvb_get_ntohl(tvb, offset);
    proto_tree_add_item(tree, hf_kafka_bytes_len, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;

    if (len < -1) {
        /* TODO expert info */
        return NULL;
    }
    else if (len == -1) {
        return NULL;
    }
    else {
        return tvb_new_subset_length(tvb, offset, len);
    }
}

static int
dissect_kafka_message(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int start_offset)
{
    proto_item *ti;
    proto_tree *subtree;
    tvbuff_t   *raw, *payload;
    int         offset = start_offset;
    guint8      codec;


    ti = proto_tree_add_text(tree, tvb, offset, -1, "Message");
    subtree = proto_item_add_subtree(ti, ett_kafka_message);

    proto_tree_add_item(subtree, hf_kafka_message_crc, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;

    proto_tree_add_item(subtree, hf_kafka_message_magic, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;

    proto_tree_add_item(subtree, hf_kafka_message_codec, tvb, offset, 1, ENC_BIG_ENDIAN);
    codec = tvb_get_guint8(tvb, offset) & 0x07;
    offset += 1;

    offset = dissect_kafka_bytes(subtree, hf_kafka_message_key, tvb, pinfo, offset);

    switch (codec) {
        case KAFKA_COMPRESSION_GZIP:
            raw = kafka_get_bytes(tree, tvb, pinfo, offset);
            offset += 4;

            if (raw) {
                payload = tvb_child_uncompress(tvb, raw, 0, tvb_length(raw));
                if (payload) {
                    add_new_data_source(pinfo, payload, "Uncompressed Message");
                    dissect_kafka_message_set(payload, pinfo, subtree, 0);
                } else {
                    /* TODO make this an expert item */
                    proto_tree_add_text(subtree, tvb, 0, tvb_length(raw), "[Failed to decompress message!]");
                    proto_tree_add_item(subtree, hf_kafka_message_value, raw, 0, -1, ENC_NA);
                }
                offset += tvb_length(raw);
            }
            else {
                proto_tree_add_bytes(subtree, hf_kafka_message_value, tvb, offset, 0, NULL);
            }
            break;
        case KAFKA_COMPRESSION_SNAPPY:
            /* We can't uncompress snappy yet... */
        case KAFKA_COMPRESSION_NONE:
        default:
            offset = dissect_kafka_bytes(subtree, hf_kafka_message_value, tvb, pinfo, offset);
    }

    proto_item_set_len(ti, offset - start_offset);

    return offset;
}

static int
dissect_kafka_message_set(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int start_offset)
{
    proto_item *ti;
    proto_tree *subtree;
    int         offset = start_offset;

    if (tvb_reported_length_remaining(tvb, offset) <= 0) {
        return offset;
    }

    ti = proto_tree_add_text(tree, tvb, offset, -1, "Message Set");
    subtree = proto_item_add_subtree(ti, ett_kafka_message_set);

    while (tvb_reported_length_remaining(tvb, offset) > 0) {
        proto_tree_add_item(subtree, hf_kafka_offset, tvb, offset, 8, ENC_BIG_ENDIAN);
        offset += 8;

        proto_tree_add_item(subtree, hf_kafka_message_size, tvb, offset, 4, ENC_BIG_ENDIAN);
        offset += 4;

        offset = dissect_kafka_message(tvb, pinfo, subtree, offset);
    }

    proto_item_set_len(ti, offset - start_offset);

    return offset;
}

/* OFFSET FETCH REQUEST/RESPONSE */

static int
dissect_kafka_offset_fetch_request_partition(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, int offset)
{
    proto_tree_add_item(tree, hf_kafka_partition_id, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;

    return offset;
}

static int
dissect_kafka_offset_fetch_request_topic(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int start_offset)
{
    proto_item *ti;
    proto_tree *subtree;
    int         offset = start_offset;

    ti = proto_tree_add_text(tree, tvb, offset, -1, "Offset Fetch Request Topic");
    subtree = proto_item_add_subtree(ti, ett_kafka_request_topic);

    offset = dissect_kafka_string(subtree, hf_kafka_topic_name, tvb, pinfo, offset);
    offset = dissect_kafka_array(subtree, tvb, pinfo, offset, &dissect_kafka_offset_fetch_request_partition);

    proto_item_set_len(ti, offset - start_offset);

    return offset;
}

static int
dissect_kafka_offset_fetch_request(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset)
{
    offset = dissect_kafka_string(tree, hf_kafka_consumer_group, tvb, pinfo, offset);

    offset = dissect_kafka_array(tree, tvb, pinfo, offset, &dissect_kafka_offset_fetch_request_topic);

    return offset;
}

static int
dissect_kafka_offset_fetch_response_partition(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, int start_offset)
{
    proto_item *ti;
    proto_tree *subtree;
    int         offset = start_offset;

    ti = proto_tree_add_text(tree, tvb, offset, -1, "Offset Fetch Response Partition");
    subtree = proto_item_add_subtree(ti, ett_kafka_request_partition);

    proto_tree_add_item(subtree, hf_kafka_partition_id, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;

    proto_tree_add_item(subtree, hf_kafka_offset, tvb, offset, 8, ENC_BIG_ENDIAN);
    offset += 8;

    offset = dissect_kafka_string(tree, hf_kafka_metadata, tvb, pinfo, offset);

    proto_tree_add_item(subtree, hf_kafka_error, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    proto_item_set_len(ti, offset - start_offset);

    return offset;
}

static int
dissect_kafka_offset_fetch_response_topic(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int start_offset)
{
    proto_item *ti;
    proto_tree *subtree;
    int         offset = start_offset;

    ti = proto_tree_add_text(tree, tvb, offset, -1, "offset fetch response topic");
    subtree = proto_item_add_subtree(ti, ett_kafka_response_topic);

    offset = dissect_kafka_string(subtree, hf_kafka_topic_name, tvb, pinfo, offset);
    offset = dissect_kafka_array(subtree, tvb, pinfo, offset, &dissect_kafka_offset_fetch_response_partition);

    proto_item_set_len(ti, offset - start_offset);

    return offset;
}

static int
dissect_kafka_offset_fetch_response(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset)
{
    return dissect_kafka_array(tree, tvb, pinfo, offset, &dissect_kafka_offset_fetch_response_topic);
}

/* METADATA REQUEST/RESPONSE */

static int
dissect_kafka_metadata_request_topic(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset)
{
    return dissect_kafka_string(tree, hf_kafka_topic_name, tvb, pinfo, offset);
}

static int
dissect_kafka_metadata_request(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset)
{
    return dissect_kafka_array(tree, tvb, pinfo, offset, &dissect_kafka_metadata_request_topic);
}

static int
dissect_kafka_metadata_broker(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int start_offset)
{
    proto_item *ti;
    proto_tree *subtree;
    int         offset = start_offset;

    ti = proto_tree_add_text(tree, tvb, offset, 14, "Broker");
    subtree = proto_item_add_subtree(ti, ett_kafka_metadata_broker);

    proto_tree_add_item(subtree, hf_kafka_broker_nodeid, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;

    offset = dissect_kafka_string(subtree, hf_kafka_broker_host, tvb, pinfo, offset);

    proto_tree_add_item(subtree, hf_kafka_broker_port, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;

    proto_item_set_len(ti, offset - start_offset);

    return offset;
}

static int
dissect_kafka_metadata_replica(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, int offset)
{
    proto_tree_add_item(tree, hf_kafka_replica, tvb, offset, 4, ENC_BIG_ENDIAN);
    return offset + 4;
}

static int
dissect_kafka_metadata_isr(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, int offset)
{
    proto_tree_add_item(tree, hf_kafka_isr, tvb, offset, 4, ENC_BIG_ENDIAN);
    return offset + 4;
}

static int
dissect_kafka_metadata_partition(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, int start_offset)
{
    proto_item *ti, *subti;
    proto_tree *subtree, *subsubtree;
    int         offset = start_offset;
    int         sub_start_offset;

    ti = proto_tree_add_text(tree, tvb, offset, -1, "Partition");
    subtree = proto_item_add_subtree(ti, ett_kafka_response_partition);

    proto_tree_add_item(subtree, hf_kafka_error, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    proto_tree_add_item(subtree, hf_kafka_partition_id, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;

    proto_tree_add_item(subtree, hf_kafka_partition_leader, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;

    sub_start_offset = offset;
    subti = proto_tree_add_text(subtree, tvb, offset, -1, "Replicas");
    subsubtree = proto_item_add_subtree(subti, ett_kafka_metadata_replicas);
    offset = dissect_kafka_array(subsubtree, tvb, pinfo, offset, &dissect_kafka_metadata_replica);
    proto_item_set_len(subti, offset - sub_start_offset);

    sub_start_offset = offset;
    subti = proto_tree_add_text(subtree, tvb, offset, -1, "Caught-Up Replicas");
    subsubtree = proto_item_add_subtree(subti, ett_kafka_metadata_isr);
    offset = dissect_kafka_array(subsubtree, tvb, pinfo, offset, &dissect_kafka_metadata_isr);
    proto_item_set_len(subti, offset - sub_start_offset);

    proto_item_set_len(ti, offset - start_offset);

    return offset;
}

static int
dissect_kafka_metadata_topic(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int start_offset)
{
    proto_item *ti;
    proto_tree *subtree;
    int         offset = start_offset;

    ti = proto_tree_add_text(tree, tvb, offset, -1, "Topic");
    subtree = proto_item_add_subtree(ti, ett_kafka_response_topic);

    proto_tree_add_item(subtree, hf_kafka_error, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    offset = dissect_kafka_string(subtree, hf_kafka_topic_name, tvb, pinfo, offset);

    offset = dissect_kafka_array(subtree, tvb, pinfo, offset, &dissect_kafka_metadata_partition);

    proto_item_set_len(ti, offset - start_offset);

    return offset;
}

static int
dissect_kafka_metadata_response(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int start_offset)
{
    proto_item *ti;
    proto_tree *subtree;
    int         offset = start_offset;

    ti = proto_tree_add_text(tree, tvb, offset, -1, "Broker Metadata");
    subtree = proto_item_add_subtree(ti, ett_kafka_metadata_brokers);
    offset = dissect_kafka_array(subtree, tvb, pinfo, offset, &dissect_kafka_metadata_broker);
    proto_item_set_len(ti, offset - start_offset);

    start_offset = offset;
    ti = proto_tree_add_text(tree, tvb, offset, -1, "Topic Metadata");
    subtree = proto_item_add_subtree(ti, ett_kafka_metadata_topics);
    offset = dissect_kafka_array(subtree, tvb, pinfo, offset, &dissect_kafka_metadata_topic);
    proto_item_set_len(ti, offset - start_offset);

    return offset;
}

/* FETCH REQUEST/RESPONSE */

static int
dissect_kafka_fetch_request_partition(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, int offset)
{
    proto_item *ti;
    proto_tree *subtree;

    ti = proto_tree_add_text(tree, tvb, offset, 16, "Fetch Request Partition");
    subtree = proto_item_add_subtree(ti, ett_kafka_request_partition);

    proto_tree_add_item(subtree, hf_kafka_partition_id, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;

    proto_tree_add_item(subtree, hf_kafka_offset, tvb, offset, 8, ENC_BIG_ENDIAN);
    offset += 8;

    proto_tree_add_item(subtree, hf_kafka_max_bytes, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;

    return offset;
}

static int
dissect_kafka_fetch_request_topic(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int start_offset)
{
    proto_item *ti;
    proto_tree *subtree;
    int         offset = start_offset;

    ti = proto_tree_add_text(tree, tvb, offset, -1, "Fetch Request Topic");
    subtree = proto_item_add_subtree(ti, ett_kafka_request_topic);

    offset = dissect_kafka_string(subtree, hf_kafka_topic_name, tvb, pinfo, offset);
    offset = dissect_kafka_array(subtree, tvb, pinfo, offset, &dissect_kafka_fetch_request_partition);

    proto_item_set_len(ti, offset - start_offset);

    return offset;
}

static int
dissect_kafka_fetch_request(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset)
{
    proto_tree_add_item(tree, hf_kafka_replica, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;

    proto_tree_add_item(tree, hf_kafka_max_wait_time, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;

    proto_tree_add_item(tree, hf_kafka_min_bytes, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;

    offset = dissect_kafka_array(tree, tvb, pinfo, offset, &dissect_kafka_fetch_request_topic);

    return offset;
}

static int
dissect_kafka_fetch_response_partition(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, int start_offset)
{
    proto_item *ti;
    proto_tree *subtree;
    int         offset = start_offset;

    ti = proto_tree_add_text(tree, tvb, offset, -1, "Fetch Response Partition");
    subtree = proto_item_add_subtree(ti, ett_kafka_response_partition);

    proto_tree_add_item(subtree, hf_kafka_partition_id, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;

    proto_tree_add_item(subtree, hf_kafka_error, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    proto_tree_add_item(subtree, hf_kafka_offset, tvb, offset, 8, ENC_BIG_ENDIAN);
    offset += 8;

    proto_tree_add_item(subtree, hf_kafka_message_set_size, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;

    offset = dissect_kafka_message_set(tvb, pinfo, subtree, offset);

    proto_item_set_len(ti, offset - start_offset);

    return offset;
}

static int
dissect_kafka_fetch_response_topic(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int start_offset)
{
    proto_item *ti;
    proto_tree *subtree;
    int         offset = start_offset;

    ti = proto_tree_add_text(tree, tvb, offset, -1, "Fetch Response Topic");
    subtree = proto_item_add_subtree(ti, ett_kafka_response_topic);

    offset = dissect_kafka_string(subtree, hf_kafka_topic_name, tvb, pinfo, offset);
    offset = dissect_kafka_array(subtree, tvb, pinfo, offset, &dissect_kafka_fetch_response_partition);

    proto_item_set_len(ti, offset - start_offset);

    return offset;
}

static int
dissect_kafka_fetch_response(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset)
{
    return dissect_kafka_array(tree, tvb, pinfo, offset, &dissect_kafka_fetch_response_topic);
}

/* PRODUCE REQUEST/RESPONSE */

static int
dissect_kafka_produce_request_partition(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, int offset)
{
    proto_item *ti;
    proto_tree *subtree;

    ti = proto_tree_add_text(tree, tvb, offset, 14, "Produce Request Partition");
    subtree = proto_item_add_subtree(ti, ett_kafka_request_partition);

    proto_tree_add_item(subtree, hf_kafka_partition_id, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;

    proto_tree_add_item(subtree, hf_kafka_message_set_size, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;

    offset = dissect_kafka_message_set(tvb, pinfo, subtree, offset);

    return offset;
}

static int
dissect_kafka_produce_request_topic(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int start_offset)
{
    proto_item *ti;
    proto_tree *subtree;
    int         offset = start_offset;

    ti = proto_tree_add_text(tree, tvb, offset, -1, "Produce Request Topic");
    subtree = proto_item_add_subtree(ti, ett_kafka_request_topic);

    offset = dissect_kafka_string(subtree, hf_kafka_topic_name, tvb, pinfo, offset);
    offset = dissect_kafka_array(subtree, tvb, pinfo, offset, &dissect_kafka_produce_request_partition);

    proto_item_set_len(ti, offset - start_offset);

    return offset;
}

static int
dissect_kafka_produce_request(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset)
{
    proto_tree_add_item(tree, hf_kafka_required_acks, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    proto_tree_add_item(tree, hf_kafka_timeout, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;

    offset = dissect_kafka_array(tree, tvb, pinfo, offset, &dissect_kafka_produce_request_topic);

    return offset;
}

static int
dissect_kafka_produce_response_partition(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, int offset)
{
    proto_item *ti;
    proto_tree *subtree;

    ti = proto_tree_add_text(tree, tvb, offset, 14, "Produce Response Partition");
    subtree = proto_item_add_subtree(ti, ett_kafka_response_partition);

    proto_tree_add_item(subtree, hf_kafka_partition_id, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;

    proto_tree_add_item(subtree, hf_kafka_error, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    proto_tree_add_item(subtree, hf_kafka_offset, tvb, offset, 8, ENC_BIG_ENDIAN);
    offset += 8;

    return offset;
}

static int
dissect_kafka_produce_response_topic(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int start_offset)
{
    proto_item *ti;
    proto_tree *subtree;
    int         offset = start_offset;

    ti = proto_tree_add_text(tree, tvb, offset, -1, "Produce Response Topic");
    subtree = proto_item_add_subtree(ti, ett_kafka_response_topic);

    offset = dissect_kafka_string(subtree, hf_kafka_topic_name, tvb, pinfo, offset);
    offset = dissect_kafka_array(subtree, tvb, pinfo, offset, &dissect_kafka_produce_response_partition);

    proto_item_set_len(ti, offset - start_offset);

    return offset;
}

static int
dissect_kafka_produce_response(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset)
{
    return dissect_kafka_array(tree, tvb, pinfo, offset, &dissect_kafka_produce_response_topic);
}

/* MAIN */

static int
dissect_kafka(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
    proto_item             *ti;
    proto_tree             *kafka_tree;
    int                     offset  = 0;
    kafka_query_response_t *matcher = NULL;
    conversation_t         *conversation;
    wmem_queue_t           *match_queue;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "Kafka");
    col_clear(pinfo->cinfo, COL_INFO);

    ti = proto_tree_add_item(tree, proto_kafka, tvb, 0, -1, ENC_NA);

    kafka_tree = proto_item_add_subtree(ti, ett_kafka);

    proto_tree_add_item(kafka_tree, hf_kafka_len, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;

    conversation = find_or_create_conversation(pinfo);
    match_queue  = (wmem_queue_t *) conversation_get_proto_data(conversation, proto_kafka);
    if (match_queue == NULL) {
        match_queue = wmem_queue_new(wmem_file_scope());
        conversation_add_proto_data(conversation, proto_kafka, match_queue);
    }

    if (PINFO_FD_VISITED(pinfo)) {
        matcher = (kafka_query_response_t *) p_get_proto_data(wmem_file_scope(), pinfo, proto_kafka, 0);
    }

    if (pinfo->destport == kafka_port) {
        /* Request */

        if (matcher == NULL) {
            matcher = wmem_new(wmem_file_scope(), kafka_query_response_t);

            matcher->api_key        = tvb_get_ntohs(tvb, offset);
            matcher->request_frame  = PINFO_FD_NUM(pinfo);
            matcher->response_found = FALSE;

            p_add_proto_data(wmem_file_scope(), pinfo, proto_kafka, 0, matcher);

            /* The kafka server always responds, except in the case of a produce
             * request whose RequiredAcks field is 0. This field is at a dynamic
             * offset into the request, so to avoid too much prefetch logic we
             * simply don't queue produce requests here. If it is a produce
             * request with a non-zero RequiredAcks field it gets queued later.
             */
            if (matcher->api_key != KAFKA_PRODUCE) {
                wmem_queue_push(match_queue, matcher);
            }
        }

        col_add_fstr(pinfo->cinfo, COL_INFO, "Kafka %s Request",
                val_to_str_const(matcher->api_key, kafka_apis, "Unknown"));

        if (matcher->response_found) {
            ti = proto_tree_add_uint(kafka_tree, hf_kafka_response_frame, tvb,
                    0, 0, matcher->response_frame);
            PROTO_ITEM_SET_GENERATED(ti);
        }

        proto_tree_add_item(kafka_tree, hf_kafka_request_api_key, tvb, offset, 2, ENC_BIG_ENDIAN);
        offset += 2;

        proto_tree_add_item(kafka_tree, hf_kafka_request_api_version, tvb, offset, 2, ENC_BIG_ENDIAN);
        offset += 2;

        proto_tree_add_item(kafka_tree, hf_kafka_correlation_id, tvb, offset, 4, ENC_BIG_ENDIAN);
        offset += 4;

        offset = dissect_kafka_string(kafka_tree, hf_kafka_client_id, tvb, pinfo, offset);

        switch (matcher->api_key) {
            /* TODO: decode other request types */
            case KAFKA_PRODUCE:
                /* Produce requests may need delayed queueing, see the more
                 * detailed comment above. */
                if (tvb_get_ntohs(tvb, offset) != 0 && !PINFO_FD_VISITED(pinfo)) {
                    wmem_queue_push(match_queue, matcher);
                }
                /*offset =*/ dissect_kafka_produce_request(tvb, pinfo, kafka_tree, offset);
                break;
            case KAFKA_OFFSET_FETCH:
                /*offset =*/ dissect_kafka_offset_fetch_request(tvb, pinfo, kafka_tree, offset);
                break;
            case KAFKA_METADATA:
                /*offset =*/ dissect_kafka_metadata_request(tvb, pinfo, kafka_tree, offset);
                break;
            case KAFKA_FETCH:
                /*offset =*/ dissect_kafka_fetch_request(tvb, pinfo, kafka_tree, offset);
                break;
        }
    }
    else {
        /* Response */

        proto_tree_add_item(kafka_tree, hf_kafka_correlation_id, tvb, offset, 4, ENC_BIG_ENDIAN);
        offset += 4;

        if (matcher == NULL) {
            if (wmem_queue_count(match_queue) == 0) {
                col_set_str(pinfo->cinfo, COL_INFO, "Kafka Response (Unknown API, Missing Request)");
                /* TODO: expert info, don't have request, can't dissect */
                return tvb_length(tvb);
            }

            matcher = (kafka_query_response_t *) wmem_queue_pop(match_queue);

            matcher->response_frame = PINFO_FD_NUM(pinfo);
            matcher->response_found = TRUE;

            p_add_proto_data(wmem_file_scope(), pinfo, proto_kafka, 0, matcher);
        }

        col_add_fstr(pinfo->cinfo, COL_INFO, "Kafka %s Response",
                val_to_str_const(matcher->api_key, kafka_apis, "Unknown"));

        ti = proto_tree_add_uint(kafka_tree, hf_kafka_request_frame, tvb,
                0, 0, matcher->request_frame);
        PROTO_ITEM_SET_GENERATED(ti);

        ti = proto_tree_add_int(kafka_tree, hf_kafka_response_api_key, tvb,
                0, 0, matcher->api_key);
        PROTO_ITEM_SET_GENERATED(ti);

        switch (matcher->api_key) {
            /* TODO: decode other response types */
            case KAFKA_PRODUCE:
                /*offset =*/ dissect_kafka_produce_response(tvb, pinfo, kafka_tree, offset);
                break;
            case KAFKA_OFFSET_FETCH:
                /*offset =*/ dissect_kafka_offset_fetch_response(tvb, pinfo, kafka_tree, offset);
                break;
            case KAFKA_METADATA:
                /*offset =*/ dissect_kafka_metadata_response(tvb, pinfo, kafka_tree, offset);
                break;
            case KAFKA_FETCH:
                /*offset =*/ dissect_kafka_fetch_response(tvb, pinfo, kafka_tree, offset);
                break;
        }

    }

    return tvb_length(tvb);
}

static int
dissect_kafka_tcp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
        void *data)
{
    tcp_dissect_pdus(tvb, pinfo, tree, TRUE, 4,
            get_kafka_pdu_len, dissect_kafka, data);

    return tvb_length(tvb);
}

void
proto_register_kafka(void)
{
    module_t *kafka_module;

    static hf_register_info hf[] = {
        { &hf_kafka_len,
            { "Length", "kafka.len",
               FT_INT32, BASE_DEC, 0, 0,
              "The length of this Kafka packet.", HFILL }
        },
        { &hf_kafka_offset,
            { "Offset", "kafka.offset",
               FT_INT64, BASE_DEC, 0, 0,
               NULL, HFILL }
        },
        { &hf_kafka_metadata,
            { "Metadata", "kafka.metadata",
               FT_STRING, BASE_NONE, 0, 0,
               NULL, HFILL }
        },
        { &hf_kafka_error,
            { "Error", "kafka.error",
               FT_INT16, BASE_DEC, VALS(kafka_errors), 0,
               NULL, HFILL }
        },
        { &hf_kafka_request_api_key,
            { "API Key", "kafka.request_key",
               FT_INT16, BASE_DEC, VALS(kafka_apis), 0,
              "Request API.", HFILL }
        },
        { &hf_kafka_response_api_key,
            { "API Key", "kafka.response_key",
               FT_INT16, BASE_DEC, VALS(kafka_apis), 0,
              "Response API.", HFILL }
        },
        { &hf_kafka_request_api_version,
            { "API Version", "kafka.version",
               FT_INT16, BASE_DEC, 0, 0,
              "Request API Version.", HFILL }
        },
        { &hf_kafka_correlation_id,
            { "Correlation ID", "kafka.correlation_id",
               FT_INT32, BASE_DEC, 0, 0,
               NULL, HFILL }
        },
        { &hf_kafka_client_id,
            { "Client ID", "kafka.client_id",
               FT_STRING, BASE_NONE, 0, 0,
              "The ID of the sending client.", HFILL }
        },
        { &hf_kafka_string_len,
            { "String Length", "kafka.string_len",
               FT_INT16, BASE_DEC, 0, 0,
              "Generic length for kafka-encoded string.", HFILL }
        },
        { &hf_kafka_bytes_len,
            { "Bytes Length", "kafka.bytes_len",
               FT_INT32, BASE_DEC, 0, 0,
              "Generic length for kafka-encoded bytes.", HFILL }
        },
        { &hf_kafka_array_count,
            { "Array Count", "kafka.array_count",
               FT_INT32, BASE_DEC, 0, 0,
               NULL, HFILL }
        },
        { &hf_kafka_required_acks,
            { "Required Acks", "kafka.required_acks",
               FT_INT16, BASE_DEC, 0, 0,
               NULL, HFILL }
        },
        { &hf_kafka_timeout,
            { "Timeout", "kafka.timeout",
               FT_INT32, BASE_DEC, 0, 0,
               NULL, HFILL }
        },
        { &hf_kafka_topic_name,
            { "Topic Name", "kafka.topic_name",
               FT_STRING, BASE_NONE, 0, 0,
               NULL, HFILL }
        },
        { &hf_kafka_partition_id,
            { "Partition ID", "kafka.partition_id",
               FT_INT32, BASE_DEC, 0, 0,
               NULL, HFILL }
        },
        { &hf_kafka_replica,
            { "Replica ID", "kafka.replica_id",
               FT_INT32, BASE_DEC, 0, 0,
               NULL, HFILL }
        },
        { &hf_kafka_isr,
            { "Caught-Up Replica ID", "kafka.isr_id",
               FT_INT32, BASE_DEC, 0, 0,
               NULL, HFILL }
        },
        { &hf_kafka_partition_leader,
            { "Leader", "kafka.leader",
               FT_INT32, BASE_DEC, 0, 0,
               NULL, HFILL }
        },
        { &hf_kafka_message_set_size,
            { "Message Set Size", "kafka.message_set_size",
               FT_INT32, BASE_DEC, 0, 0,
               NULL, HFILL }
        },
        { &hf_kafka_message_size,
            { "Message Size", "kafka.message_size",
               FT_INT32, BASE_DEC, 0, 0,
               NULL, HFILL }
        },
        { &hf_kafka_message_crc,
            { "CRC32", "kafka.message_crc",
               FT_UINT32, BASE_HEX, 0, 0,
               NULL, HFILL }
        },
        { &hf_kafka_message_magic,
            { "Magic Byte", "kafka.message_magic",
               FT_INT8, BASE_DEC, 0, 0,
               NULL, HFILL }
        },
        { &hf_kafka_message_codec,
            { "Compression Codec", "kafka.message_codec",
               FT_INT8, BASE_DEC, VALS(kafka_codecs), 0x03,
               NULL, HFILL }
        },
        { &hf_kafka_message_key,
            { "Key", "kafka.message_key",
               FT_BYTES, BASE_NONE, 0, 0,
               NULL, HFILL }
        },
        { &hf_kafka_message_value,
            { "Value", "kafka.message_value",
               FT_BYTES, BASE_NONE, 0, 0,
               NULL, HFILL }
        },
        { &hf_kafka_consumer_group,
            { "Consumer Group", "kafka.consumer_group",
               FT_STRING, BASE_NONE, 0, 0,
               NULL, HFILL }
        },
        { &hf_kafka_request_frame,
            { "Request Frame", "kafka.request_frame",
               FT_FRAMENUM, BASE_NONE, 0, 0,
               NULL, HFILL }
        },
        { &hf_kafka_broker_nodeid,
            { "Node ID", "kafka.node_id",
               FT_INT32, BASE_DEC, 0, 0,
               NULL, HFILL }
        },
        { &hf_kafka_broker_host,
            { "Host", "kafka.host",
               FT_STRING, BASE_NONE, 0, 0,
               NULL, HFILL }
        },
        { &hf_kafka_broker_port,
            { "Port", "kafka.port",
               FT_INT32, BASE_DEC, 0, 0,
               NULL, HFILL }
        },
        { &hf_kafka_min_bytes,
            { "Min Bytes", "kafka.min_bytes",
               FT_INT32, BASE_DEC, 0, 0,
               "The minimum number of bytes of messages that must be available"
                   " to give a response.",
               HFILL }
        },
        { &hf_kafka_max_bytes,
            { "Max Bytes", "kafka.max_bytes",
               FT_INT32, BASE_DEC, 0, 0,
               "The maximum bytes to include in the message set for this"
                   " partition. This helps bound the size of the response.",
               HFILL }
        },
        { &hf_kafka_max_wait_time,
            { "Max Wait Time", "kafka.max_wait_time",
               FT_INT32, BASE_DEC, 0, 0,
               "The maximum amount of time in milliseconds to block waiting if"
                   " insufficient data is available at the time the request is"
                   " issued.",
               HFILL }
        },
        { &hf_kafka_response_frame,
            { "Response Frame", "kafka.reponse_frame",
               FT_FRAMENUM, BASE_NONE, 0, 0,
               NULL, HFILL }
        }
    };

    static gint *ett[] = {
        &ett_kafka,
        &ett_kafka_message,
        &ett_kafka_message_set,
        &ett_kafka_metadata_isr,
        &ett_kafka_metadata_replicas,
        &ett_kafka_metadata_broker,
        &ett_kafka_metadata_brokers,
        &ett_kafka_metadata_topics,
        &ett_kafka_request_topic,
        &ett_kafka_request_partition,
        &ett_kafka_response_topic,
        &ett_kafka_response_partition
    };

    proto_kafka = proto_register_protocol("Kafka",
            "Kafka", "kafka");

    proto_register_field_array(proto_kafka, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    kafka_module = prefs_register_protocol(proto_kafka,
            proto_reg_handoff_kafka);

    /* Register an example port preference */
    prefs_register_uint_preference(kafka_module, "tcp.port", "Broker TCP Port",
            "Kafka broker's TCP port",
            10, &kafka_port);
}

void
proto_reg_handoff_kafka(void)
{
    static gboolean initialized = FALSE;
    static dissector_handle_t kafka_handle;
    static int currentPort;

    if (!initialized) {
        kafka_handle = new_create_dissector_handle(dissect_kafka_tcp,
                proto_kafka);
        initialized = TRUE;

    } else {
        dissector_delete_uint("tcp.port", currentPort, kafka_handle);
    }

    currentPort = kafka_port;

    dissector_add_uint("tcp.port", currentPort, kafka_handle);
}

/*
 * Editor modelines  -  http://www.wireshark.org/tools/modelines.html
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
