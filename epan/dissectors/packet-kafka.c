/* packet-kafka.c
 * Routines for Kafka Protocol dissection (version 0.8 and later)
 * Copyright 2013, Evan Huus <eapache@gmail.com>
 *
 * https://cwiki.apache.org/confluence/display/KAFKA/A+Guide+To+The+Kafka+Protocol
 * http://kafka.apache.org/protocol.html
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

#include <epan/packet.h>
#include <epan/expert.h>
#include <epan/prefs.h>
#include <epan/prefs-int.h>
#include <epan/proto_data.h>
#ifdef HAVE_SNAPPY
#include <snappy-c.h>
#endif
#include "packet-tcp.h"

void proto_register_kafka(void);
void proto_reg_handoff_kafka(void);

static int proto_kafka                  = -1;
static int hf_kafka_len                 = -1;
static int hf_kafka_request_api_key     = -1;
static int hf_kafka_response_api_key    = -1;
static int hf_kafka_request_api_version = -1;
static int hf_kafka_response_api_version = -1;
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
static int hf_kafka_message_timestamp   = -1;
static int hf_kafka_message_key         = -1;
static int hf_kafka_message_value       = -1;
static int hf_kafka_request_frame       = -1;
static int hf_kafka_response_frame      = -1;
static int hf_kafka_consumer_group      = -1;
static int hf_kafka_offset              = -1;
static int hf_kafka_offset_time         = -1;
static int hf_kafka_max_offsets         = -1;
static int hf_kafka_metadata            = -1;
static int hf_kafka_error               = -1;
static int hf_kafka_broker_nodeid       = -1;
static int hf_kafka_broker_host         = -1;
static int hf_kafka_broker_port         = -1;
static int hf_kafka_broker_rack         = -1;
static int hf_kafka_cluster_id          = -1;
static int hf_kafka_controller_id       = -1;
static int hf_kafka_is_internal         = -1;
static int hf_kafka_min_bytes           = -1;
static int hf_kafka_max_bytes           = -1;
static int hf_kafka_max_wait_time       = -1;
static int hf_kafka_throttle_time       = -1;
static int hf_kafka_api_versions_api_key     = -1;
static int hf_kafka_api_versions_min_version = -1;
static int hf_kafka_api_versions_max_version = -1;

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
static gint ett_kafka_api_versions = -1;

static expert_field ei_kafka_message_decompress = EI_INIT;
static expert_field ei_kafka_bad_string_length = EI_INIT;
static expert_field ei_kafka_bad_bytes_length = EI_INIT;

#define KAFKA_PRODUCE             0
#define KAFKA_FETCH               1
#define KAFKA_OFFSETS             2
#define KAFKA_METADATA            3
#define KAFKA_LEADER_AND_ISR      4
#define KAFKA_STOP_REPLICA        5
#define KAFKA_UPDATE_METADATA     6
#define KAFKA_CONTROLLED_SHUTDOWN 7
#define KAFKA_OFFSET_COMMIT       8
#define KAFKA_OFFSET_FETCH        9
#define KAFKA_GROUP_COORDINATOR  10
#define KAFKA_JOIN_GROUP         11
#define KAFKA_HEARTBEAT          12
#define KAFKA_LEAVE_GROUP        13
#define KAFKA_SYNC_GROUP         14
#define KAFKA_DESCRIBE_GROUPS    15
#define KAFKA_LIST_GROUPS        16
#define KAFKA_SASL_HANDSHAKE     17
#define KAFKA_API_VERSIONS       18
#define KAFKA_CREATE_TOPICS      19
#define KAFKA_DELETE_TOPICS      20
static const value_string kafka_apis[] = {
    { KAFKA_PRODUCE,             "Produce"            },
    { KAFKA_FETCH,               "Fetch"              },
    { KAFKA_OFFSETS,             "Offsets"            },
    { KAFKA_METADATA,            "Metadata"           },
    { KAFKA_LEADER_AND_ISR,      "LeaderAndIsr"       },
    { KAFKA_STOP_REPLICA,        "StopReplica"        },
    { KAFKA_UPDATE_METADATA,     "UpdateMetadata"     },
    { KAFKA_CONTROLLED_SHUTDOWN, "ControlledShutdown" },
    { KAFKA_OFFSET_COMMIT,       "OffsetCommit"       },
    { KAFKA_OFFSET_FETCH,        "OffsetFetch"        },
    { KAFKA_GROUP_COORDINATOR,   "GroupCoordinator"   },
    { KAFKA_JOIN_GROUP,          "JoinGroup"          },
    { KAFKA_HEARTBEAT,           "Heatbeat"           },
    { KAFKA_LEAVE_GROUP,         "LeaveGroup"         },
    { KAFKA_SYNC_GROUP,          "SyncGroup"          },
    { KAFKA_DESCRIBE_GROUPS,     "DescribeGroups"     },
    { KAFKA_LIST_GROUPS,         "ListGroups"         },
    { KAFKA_SASL_HANDSHAKE,      "SaslHandshake"      },
    { KAFKA_API_VERSIONS,        "ApiVersions"        },
    { KAFKA_CREATE_TOPICS,       "CreateTopics"       },
    { KAFKA_DELETE_TOPICS,       "DeleteTopics"       },
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
    { 17, "Invalid topic" },
    { 18, "Message batch larger than configured server segment size" },
    { 19, "Not enough in-sync replicas" },
    { 20, "Message(s) written to insufficient number of in-sync replicas" },
    { 21, "Invalid required acks value" },
    { 22, "Specified group generation id is not valid" },
    { 23, "Inconsistent group protocol" },
    { 24, "Invalid group.id" },
    { 25, "Unknown member" },
    { 26, "Invalid session timeout" },
    { 27, "Group rebalance in progress" },
    { 28, "Commit offset data size is not valid" },
    { 29, "Topic authorization failed" },
    { 30, "Group authorization failed" },
    { 31, "Cluster authorization failed" },
    { 32, "Invalid timestamp" },
    { 33, "Unsupported SASL mechanism" },
    { 34, "Illegal SASL state" },
    { 35, "Unsupported version" },
    { 36, "Topic already exists" },
    { 37, "Invalid number of partitions" },
    { 38, "Invalid replication-factor" },
    { 39, "Invalid replica assignment" },
    { 40, "Invalid configuration" },
    { 41, "Not controller" },
    { 42, "Invalid request" },
    { 0, NULL }
};

#define KAFKA_COMPRESSION_NONE   0
#define KAFKA_COMPRESSION_GZIP   1
#define KAFKA_COMPRESSION_SNAPPY 2
#define KAFKA_COMPRESSION_LZ4    3
static const value_string kafka_codecs[] = {
    { KAFKA_COMPRESSION_NONE,   "None"   },
    { KAFKA_COMPRESSION_GZIP,   "Gzip"   },
    { KAFKA_COMPRESSION_SNAPPY, "Snappy" },
    { KAFKA_COMPRESSION_LZ4,    "LZ4"    },
    { 0, NULL }
};
#ifdef HAVE_SNAPPY
static const guint8 kafka_xerial_header[8] = {0x82, 0x53, 0x4e, 0x41, 0x50, 0x50, 0x59, 0x00};
#endif

/* List/range of TCP ports to register */
static range_t *current_kafka_tcp_range = NULL;

typedef guint16 kafka_api_version_t;

typedef struct _kafka_query_response_t {
    gint16   api_key;
    kafka_api_version_t api_version;
    guint32  request_frame;
    guint32  response_frame;
    gboolean response_found;
} kafka_query_response_t;


/* Some values to temporarily remember during dissection */
typedef struct kafka_packet_values_t {
    guint32 partition_id;
    gint64  offset;
} kafka_packet_values_t;

/* Forward declaration (dissect_kafka_message_set() and dissect_kafka_message() call each other...) */
static int
dissect_kafka_message_set(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int start_offset, gboolean has_length_field);


/* HELPERS */

static guint
get_kafka_pdu_len(packet_info *pinfo _U_, tvbuff_t *tvb, int offset, void *data _U_)
{
    return 4 + tvb_get_ntohl(tvb, offset);
}

static int
dissect_kafka_array(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, int offset,
                    kafka_api_version_t api_version,
                    int(*func)(tvbuff_t*, packet_info*, proto_tree*, int, kafka_api_version_t))
{
    gint32 count, i;

    count = (gint32) tvb_get_ntohl(tvb, offset);
    proto_tree_add_item(tree, hf_kafka_array_count, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;

    for (i=0; i<count; i++) {
        offset = func(tvb, pinfo, tree, offset, api_version);
    }

    return offset;
}

static int
dissect_kafka_string(proto_tree *tree, int hf_item, tvbuff_t *tvb, packet_info *pinfo, int offset,
                     int *p_string_offset, int *p_string_len)
{
    gint16 len;
    proto_item *pi;

    /* String length */
    len = (gint16) tvb_get_ntohs(tvb, offset);
    pi = proto_tree_add_item(tree, hf_kafka_string_len, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    if (p_string_offset != NULL) *p_string_offset = offset;

    if (len < -1) {
        expert_add_info(pinfo, pi, &ei_kafka_bad_string_length);
    }
    else if (len == -1) {
        /* -1 indicates a NULL string */
        proto_tree_add_string(tree, hf_item, tvb, offset, 0, NULL);

    }
    else {
        /* Add the string itself. */
        proto_tree_add_item(tree, hf_item, tvb, offset, len, ENC_NA|ENC_ASCII);
        offset += len;
    }

    if (p_string_len != NULL) *p_string_len = len;

    return offset;
}

static int
dissect_kafka_bytes(proto_tree *tree, int hf_item, tvbuff_t *tvb, packet_info *pinfo, int offset,
                    int *p_bytes_offset, int *p_bytes_len)
{
    gint32 len;
    proto_item *pi;

    /* Length */
    len = (gint32) tvb_get_ntohl(tvb, offset);
    pi = proto_tree_add_item(tree, hf_kafka_bytes_len, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;

    if (p_bytes_offset != NULL) *p_bytes_offset = offset;

    if (len < -1) {
        expert_add_info(pinfo, pi, &ei_kafka_bad_bytes_length);
    }
    else if (len == -1) {
        proto_tree_add_bytes(tree, hf_item, tvb, offset, 0, NULL);
    }
    else {
        proto_tree_add_item(tree, hf_item, tvb, offset, len, ENC_NA);
        offset += len;
    }

    if (p_bytes_len != NULL) *p_bytes_len = len;

    return offset;
}

static tvbuff_t *
kafka_get_bytes(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, int offset)
{
    gint32 len;
    proto_item *pi;

    len = (gint32) tvb_get_ntohl(tvb, offset);
    pi = proto_tree_add_item(tree, hf_kafka_bytes_len, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;

    if (len < -1) {
        expert_add_info(pinfo, pi, &ei_kafka_bad_bytes_length);
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
dissect_kafka_timestamp(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, int hf_item, int offset)
{
    nstime_t nstime;
    guint64  milliseconds;

    milliseconds = tvb_get_ntoh64(tvb, offset);
    nstime.secs  = milliseconds / 1000;
    nstime.nsecs = ((int)milliseconds % 1000) * 1000000;

    proto_tree_add_time(tree, hf_item, tvb, offset, 8, &nstime);
    offset += 8;

    return offset;
}

static int
dissect_kafka_message(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int start_offset)
{
    proto_item *ti, *decrypt_item;
    proto_tree *subtree;
    tvbuff_t   *raw, *payload;
    int         offset = start_offset;
    gint8       magic_byte;
    guint8      codec;
    guint       bytes_length = 0;


    subtree = proto_tree_add_subtree(tree, tvb, offset, -1, ett_kafka_message, &ti, "Message");

    /* CRC */
    proto_tree_add_item(subtree, hf_kafka_message_crc, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;

    /* Magic */
    magic_byte = tvb_get_guint8(tvb, offset);
    proto_tree_add_item(subtree, hf_kafka_message_magic, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;

    /* Codec */
    proto_tree_add_item(subtree, hf_kafka_message_codec, tvb, offset, 1, ENC_BIG_ENDIAN);
    codec = tvb_get_guint8(tvb, offset) & 0x07;
    offset += 1;

    if (magic_byte >= 1) {
        /* Timestamp */
        offset = dissect_kafka_timestamp(tvb, pinfo, subtree, hf_kafka_message_timestamp, offset);
    }

    offset = dissect_kafka_bytes(subtree, hf_kafka_message_key, tvb, pinfo, offset, NULL, &bytes_length);

    switch (codec) {
        case KAFKA_COMPRESSION_GZIP:
            raw = kafka_get_bytes(subtree, tvb, pinfo, offset);
            offset += 4;

            if (raw) {
                payload = tvb_child_uncompress(tvb, raw, 0, tvb_captured_length(raw));
                if (payload) {
                    add_new_data_source(pinfo, payload, "Uncompressed Message");
                    dissect_kafka_message_set(payload, pinfo, subtree, 0, FALSE);
                } else {
                    decrypt_item = proto_tree_add_item(subtree, hf_kafka_message_value, raw, 0, -1, ENC_NA);
                    expert_add_info(pinfo, decrypt_item, &ei_kafka_message_decompress);
                }
                offset += tvb_captured_length(raw);
            }
            else {
                proto_tree_add_bytes(subtree, hf_kafka_message_value, tvb, offset, 0, NULL);
            }

            /* Add to summary */
            col_append_fstr(pinfo->cinfo, COL_INFO, " [%u bytes GZIPd]", bytes_length);
            proto_item_append_text(ti, " (%u bytes GZIPd)", bytes_length);

            break;
        case KAFKA_COMPRESSION_SNAPPY:
#ifdef HAVE_SNAPPY
            raw = kafka_get_bytes(subtree, tvb, pinfo, offset);
            offset += 4;
            if (raw) {
                guint compressed_size = tvb_reported_length(raw);
                guint8 *data = (guint8*)tvb_memdup(wmem_packet_scope(), raw, 0, compressed_size);
                size_t uncompressed_size;
                snappy_status ret = SNAPPY_INVALID_INPUT;

                if (tvb_memeql(raw, 0, kafka_xerial_header, sizeof(kafka_xerial_header)) == 0) {
                    /* xerial framing format */
                    guint chunk_size, pos = 16;

                    payload = tvb_new_composite();
                    while (pos < compressed_size) {
                        chunk_size = tvb_get_ntohl(raw, pos);
                        pos += 4;
                        ret = snappy_uncompressed_length(&data[pos], chunk_size, &uncompressed_size);
                        if (ret == SNAPPY_OK) {
                            guint8 *decompressed_buffer = (guint8*)wmem_alloc(pinfo->pool, uncompressed_size);

                            ret = snappy_uncompress(&data[pos], chunk_size, decompressed_buffer, &uncompressed_size);
                            if (ret == SNAPPY_OK) {
                                tvb_composite_append(payload,
                                                     tvb_new_child_real_data(tvb, decompressed_buffer,
                                                                             (guint32)uncompressed_size, (guint32)uncompressed_size));
                            } else {
                                wmem_free(pinfo->pool, decompressed_buffer);
                                break;
                            }
                        }
                        pos += chunk_size;
                    }
                    tvb_composite_finalize(payload);
                } else {
                    /* unframed format */
                    ret = snappy_uncompressed_length(data, compressed_size, &uncompressed_size);
                    if (ret == SNAPPY_OK) {
                        guint8 *decompressed_buffer = (guint8*)wmem_alloc(pinfo->pool, uncompressed_size);

                        ret = snappy_uncompress(data, compressed_size, decompressed_buffer, &uncompressed_size);
                        if (ret == SNAPPY_OK) {
                            payload = tvb_new_child_real_data(tvb, decompressed_buffer,
                                                             (guint32)uncompressed_size, (guint32)uncompressed_size);
                        } else {
                            wmem_free(pinfo->pool, decompressed_buffer);
                        }
                    }
                }
                if (ret == SNAPPY_OK) {
                    add_new_data_source(pinfo, payload, "Uncompressed Message");
                    dissect_kafka_message_set(payload, pinfo, subtree, 0, FALSE);
                } else {
                    decrypt_item = proto_tree_add_item(subtree, hf_kafka_message_value, raw, 0, -1, ENC_NA);
                    expert_add_info(pinfo, decrypt_item, &ei_kafka_message_decompress);
                }
                offset += tvb_captured_length(raw);
            }
            break;
#endif
        case KAFKA_COMPRESSION_LZ4:
        case KAFKA_COMPRESSION_NONE:
        default:
            offset = dissect_kafka_bytes(subtree, hf_kafka_message_value, tvb, pinfo, offset, NULL, &bytes_length);

            /* Add to summary */
            col_append_fstr(pinfo->cinfo, COL_INFO, " [%u bytes]", bytes_length);
            proto_item_append_text(ti, " (%u bytes)", bytes_length);
    }

    proto_item_set_len(ti, offset - start_offset);

    return offset;
}

static int
dissect_kafka_message_set(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int start_offset, gboolean has_length_field)
{
    proto_item *ti;
    proto_tree *subtree;
    gint        len;
    int         offset = start_offset;
    int         messages = 0;

    if (has_length_field) {
        proto_tree_add_item(tree, hf_kafka_message_set_size, tvb, offset, 4, ENC_BIG_ENDIAN);
        len = (gint)tvb_get_ntohl(tvb, offset);
        offset += 4;
        start_offset += 4;
    }
    else {
        len = tvb_reported_length_remaining(tvb, offset);
    }

    if (len <= 0) {
        return offset;
    }

    subtree = proto_tree_add_subtree(tree, tvb, offset, -1, ett_kafka_message_set, &ti, "Message Set");

    while (offset - start_offset < len) {
        proto_tree_add_item(subtree, hf_kafka_offset, tvb, offset, 8, ENC_BIG_ENDIAN);
        offset += 8;

        proto_tree_add_item(subtree, hf_kafka_message_size, tvb, offset, 4, ENC_BIG_ENDIAN);
        offset += 4;

        offset = dissect_kafka_message(tvb, pinfo, subtree, offset);
        messages += 1;
    }

    proto_item_append_text(ti, " (%d Messages)", messages);
    proto_item_set_len(ti, offset - start_offset);

    return offset;
}

/* OFFSET FETCH REQUEST/RESPONSE */

static int
dissect_kafka_partition_id(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, int offset,
                           kafka_api_version_t api_version _U_)
{
    proto_tree_add_item(tree, hf_kafka_partition_id, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;

    return offset;
}

static int
dissect_kafka_partition_id_get_value(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, int offset, kafka_packet_values_t* packet_values)
{
    proto_tree_add_item(tree, hf_kafka_partition_id, tvb, offset, 4, ENC_BIG_ENDIAN);
    if (packet_values != NULL) {
        packet_values->partition_id = tvb_get_ntohl(tvb, offset);
    }
    offset += 4;

    return offset;
}

static int
dissect_kafka_offset_get_value(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, int offset, kafka_packet_values_t* packet_values)
{
    proto_tree_add_item(tree, hf_kafka_offset, tvb, offset, 8, ENC_BIG_ENDIAN);
    if (packet_values != NULL) {
        packet_values->offset = tvb_get_ntoh64(tvb, offset);
    }
    offset += 8;

    return offset;
}

static int
dissect_kafka_offset(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, int offset,
                     kafka_api_version_t api_version _U_)
{
    proto_tree_add_item(tree, hf_kafka_offset, tvb, offset, 8, ENC_BIG_ENDIAN);
    offset += 8;

    return offset;
}

static int
dissect_kafka_offset_time(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, int offset,
                          kafka_api_version_t api_version _U_)
{
    proto_tree_add_item(tree, hf_kafka_offset_time, tvb, offset, 8, ENC_BIG_ENDIAN);
    offset += 8;

    return offset;
}

static int
dissect_kafka_offset_fetch_request_topic(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int start_offset,
                                         kafka_api_version_t api_version)
{
    proto_item *ti;
    proto_tree *subtree;
    int         offset = start_offset;
    guint32     count;

    subtree = proto_tree_add_subtree(tree, tvb, offset, -1, ett_kafka_request_topic, &ti, "Offset Fetch Request Topic");

    offset = dissect_kafka_string(subtree, hf_kafka_topic_name, tvb, pinfo, offset, NULL, NULL);
    count = (gint32)tvb_get_ntohl(tvb, offset);
    offset = dissect_kafka_array(subtree, tvb, pinfo, offset, api_version, &dissect_kafka_partition_id);

    proto_item_set_len(ti, offset - start_offset);
    proto_item_append_text(ti, " (%u partitions)", count);

    return offset;
}

static int
dissect_kafka_offset_fetch_request(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset,
                                   kafka_api_version_t api_version)
{
    offset = dissect_kafka_string(tree, hf_kafka_consumer_group, tvb, pinfo, offset, NULL, NULL);
    offset = dissect_kafka_array(tree, tvb, pinfo, offset, api_version,
                                 &dissect_kafka_offset_fetch_request_topic);

    return offset;
}

static int dissect_kafka_error(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset)
{
    guint16 error = tvb_get_ntohs(tvb, offset);
    proto_tree_add_item(tree, hf_kafka_error, tvb, offset, 2, ENC_BIG_ENDIAN);
    /* Show error in Info column */
    if (error != 0) {
        col_append_fstr(pinfo->cinfo, COL_INFO,
                        " [%s] ", val_to_str_const(error, kafka_errors, "Unknown"));
    }
    offset += 2;
    return offset;
}

static int
dissect_kafka_offset_fetch_response_partition(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                                              int start_offset, kafka_api_version_t api_version)
{
    proto_item *ti;
    proto_tree *subtree;
    int         offset = start_offset;
    kafka_packet_values_t packet_values;
    memset(&packet_values, 0, sizeof(packet_values));

    subtree = proto_tree_add_subtree(tree, tvb, offset, -1, ett_kafka_request_partition, &ti, "Offset Fetch Response Partition");

    offset = dissect_kafka_partition_id_get_value(tvb, pinfo, subtree, offset, &packet_values);
    offset = dissect_kafka_offset(tvb, pinfo, subtree, offset, api_version);

    offset = dissect_kafka_string(subtree, hf_kafka_metadata, tvb, pinfo, offset, NULL, NULL);

    offset = dissect_kafka_error(tvb, pinfo, subtree, offset);

    proto_item_append_text(ti, " (Partition-ID=%u, Offset=%" G_GINT64_MODIFIER "u)",
                           packet_values.partition_id, packet_values.offset);

    proto_item_set_len(ti, offset - start_offset);

    return offset;
}

static int
dissect_kafka_offset_fetch_response_topic(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int start_offset,
                                          kafka_api_version_t api_version)
{
    proto_item *ti;
    proto_tree *subtree;
    int         offset = start_offset;

    subtree = proto_tree_add_subtree(tree, tvb, offset, -1, ett_kafka_response_topic, &ti, "offset fetch response topic");

    offset = dissect_kafka_string(subtree, hf_kafka_topic_name, tvb, pinfo, offset, NULL, NULL);
    offset = dissect_kafka_array(subtree, tvb, pinfo, offset, api_version,
                                 &dissect_kafka_offset_fetch_response_partition);

    proto_item_set_len(ti, offset - start_offset);

    return offset;
}

static int
dissect_kafka_offset_fetch_response(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset,
                                    kafka_api_version_t api_version)
{
    return dissect_kafka_array(tree, tvb, pinfo, offset, api_version,
                               &dissect_kafka_offset_fetch_response_topic);
}

/* METADATA REQUEST/RESPONSE */

static int
dissect_kafka_metadata_request_topic(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset,
                                     kafka_api_version_t api_version _U_)
{
    return dissect_kafka_string(tree, hf_kafka_topic_name, tvb, pinfo, offset, NULL, NULL);
}

static int
dissect_kafka_metadata_request(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset,
                               kafka_api_version_t api_version)
{
    return dissect_kafka_array(tree, tvb, pinfo, offset, api_version,
                               &dissect_kafka_metadata_request_topic);
}

static int
dissect_kafka_metadata_broker(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int start_offset,
                              kafka_api_version_t api_version)
{
    proto_item *ti;
    proto_tree *subtree;
    int         offset = start_offset;
    guint32     nodeid;
    int         host_start, host_len;
    guint32     broker_port;

    subtree = proto_tree_add_subtree(tree, tvb, offset, 14, ett_kafka_metadata_broker, &ti, "Broker");

    nodeid = tvb_get_ntohl(tvb, offset);
    proto_tree_add_item(subtree, hf_kafka_broker_nodeid, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;

    offset = dissect_kafka_string(subtree, hf_kafka_broker_host, tvb, pinfo, offset, &host_start, &host_len);

    broker_port = tvb_get_ntohl(tvb, offset);
    proto_tree_add_item(subtree, hf_kafka_broker_port, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;

    if (api_version >= 1) {
        offset = dissect_kafka_string(subtree, hf_kafka_broker_rack, tvb, pinfo, offset, NULL, NULL);
    }

    proto_item_append_text(ti, " (node %u: %s:%u)",
                           nodeid,
                           tvb_get_string_enc(wmem_packet_scope(), tvb,
                           host_start, host_len, ENC_UTF_8|ENC_NA),
                           broker_port);

    proto_item_set_len(ti, offset - start_offset);

    return offset;
}

static int
dissect_kafka_metadata_replica(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, int offset,
                               kafka_api_version_t api_version _U_)
{
    proto_tree_add_item(tree, hf_kafka_replica, tvb, offset, 4, ENC_BIG_ENDIAN);
    return offset + 4;
}

static int
dissect_kafka_metadata_isr(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, int offset,
                           kafka_api_version_t api_version _U_)
{
    proto_tree_add_item(tree, hf_kafka_isr, tvb, offset, 4, ENC_BIG_ENDIAN);
    return offset + 4;
}

static int
dissect_kafka_metadata_partition(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int start_offset,
                                 kafka_api_version_t api_version)
{
    proto_item *ti, *subti;
    proto_tree *subtree, *subsubtree;
    int         offset = start_offset;
    int         sub_start_offset;

    subtree = proto_tree_add_subtree(tree, tvb, offset, -1, ett_kafka_response_partition, &ti, "Partition");

    offset = dissect_kafka_error(tvb, pinfo, subtree, offset);

    offset = dissect_kafka_partition_id(tvb, pinfo, subtree, offset, api_version);

    proto_tree_add_item(subtree, hf_kafka_partition_leader, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;

    sub_start_offset = offset;
    subsubtree = proto_tree_add_subtree(subtree, tvb, offset, -1, ett_kafka_metadata_replicas, &subti, "Replicas");
    offset = dissect_kafka_array(subsubtree, tvb, pinfo, offset, api_version, &dissect_kafka_metadata_replica);
    proto_item_set_len(subti, offset - sub_start_offset);

    sub_start_offset = offset;
    subsubtree = proto_tree_add_subtree(subtree, tvb, offset, -1, ett_kafka_metadata_isr, &subti, "Caught-Up Replicas");
    offset = dissect_kafka_array(subsubtree, tvb, pinfo, offset, api_version, &dissect_kafka_metadata_isr);
    proto_item_set_len(subti, offset - sub_start_offset);

    proto_item_set_len(ti, offset - start_offset);

    return offset;
}

static int
dissect_kafka_metadata_topic(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int start_offset,
                             kafka_api_version_t api_version)
{
    proto_item *ti;
    proto_tree *subtree;
    int         offset = start_offset;
    int         name_start, name_length;

    subtree = proto_tree_add_subtree(tree, tvb, offset, -1, ett_kafka_response_topic, &ti, "Topic");

    offset = dissect_kafka_error(tvb, pinfo, subtree, offset);

    offset = dissect_kafka_string(subtree, hf_kafka_topic_name, tvb, pinfo, offset, &name_start, &name_length);
    proto_item_append_text(ti, " (%s)",
                           tvb_get_string_enc(wmem_packet_scope(), tvb,
                           name_start, name_length, ENC_UTF_8|ENC_NA));

    if (api_version >= 1) {
        proto_tree_add_item(subtree, hf_kafka_is_internal, tvb, offset, 1, ENC_NA);
        offset += 1;
    }

    offset = dissect_kafka_array(subtree, tvb, pinfo, offset, api_version, &dissect_kafka_metadata_partition);

    proto_item_set_len(ti, offset - start_offset);

    return offset;
}

static int
dissect_kafka_metadata_response(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int start_offset,
                                kafka_api_version_t api_version)
{
    proto_item *ti;
    proto_tree *subtree;
    int         offset = start_offset;

    subtree = proto_tree_add_subtree(tree, tvb, offset, -1, ett_kafka_metadata_brokers, &ti, "Broker Metadata");
    offset = dissect_kafka_array(subtree, tvb, pinfo, offset, api_version, &dissect_kafka_metadata_broker);
    proto_item_set_len(ti, offset - start_offset);

    if (api_version >= 2) {
        offset = dissect_kafka_string(tree, hf_kafka_cluster_id, tvb, pinfo, offset, NULL, NULL);
    }

    if (api_version >= 1) {
        proto_tree_add_item(tree, hf_kafka_controller_id, tvb, offset, 4, ENC_BIG_ENDIAN);
        offset += 4;
    }

    start_offset = offset;
    subtree = proto_tree_add_subtree(tree, tvb, offset, -1, ett_kafka_metadata_topics, &ti, "Topic Metadata");
    offset = dissect_kafka_array(subtree, tvb, pinfo, offset, api_version, &dissect_kafka_metadata_topic);
    proto_item_set_len(ti, offset - start_offset);

    return offset;
}

/* FETCH REQUEST/RESPONSE */

static int
dissect_kafka_fetch_request_partition(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset,
                                      kafka_api_version_t api_version _U_)
{
    proto_item *ti;
    proto_tree *subtree;
    kafka_packet_values_t packet_values;
    memset(&packet_values, 0, sizeof(packet_values));

    subtree = proto_tree_add_subtree(tree, tvb, offset, 16, ett_kafka_request_partition, &ti, "Fetch Request Partition");

    offset = dissect_kafka_partition_id_get_value(tvb, pinfo, subtree, offset, &packet_values);

    offset = dissect_kafka_offset_get_value(tvb, pinfo, subtree, offset, &packet_values);

    proto_tree_add_item(subtree, hf_kafka_max_bytes, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;

    proto_item_append_text(ti, " (Partition-ID=%u, Offset=%" G_GINT64_MODIFIER "u)",
                           packet_values.partition_id, packet_values.offset);

    return offset;
}

static int
dissect_kafka_fetch_request_topic(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int start_offset,
                                  kafka_api_version_t api_version)
{
    proto_item *ti;
    proto_tree *subtree;
    int         offset = start_offset;
    guint32     count;
    int         name_start, name_length;

    subtree = proto_tree_add_subtree(tree, tvb, offset, -1, ett_kafka_request_topic, &ti, "Fetch Request Topic");

    offset = dissect_kafka_string(subtree, hf_kafka_topic_name, tvb, pinfo, offset, &name_start, &name_length);
    count = tvb_get_ntohl(tvb, offset);
    offset = dissect_kafka_array(subtree, tvb, pinfo, offset, api_version,
                                 &dissect_kafka_fetch_request_partition);

    proto_item_set_len(ti, offset - start_offset);
    proto_item_append_text(ti, " (%u partitions)", count);

    return offset;
}

static int
dissect_kafka_fetch_request(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset,
                            kafka_api_version_t api_version)
{
    proto_tree_add_item(tree, hf_kafka_replica, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;

    proto_tree_add_item(tree, hf_kafka_max_wait_time, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;

    proto_tree_add_item(tree, hf_kafka_min_bytes, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;

    if (api_version >= 3) {
        proto_tree_add_item(tree, hf_kafka_max_bytes, tvb, offset, 4, ENC_BIG_ENDIAN);
        offset += 4;
    }

    offset = dissect_kafka_array(tree, tvb, pinfo, offset, api_version, &dissect_kafka_fetch_request_topic);

    return offset;
}

static int
dissect_kafka_fetch_response_partition(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int start_offset,
                                       kafka_api_version_t api_version _U_)
{
    proto_item *ti;
    proto_tree *subtree;
    int         offset = start_offset;
    kafka_packet_values_t packet_values;
    memset(&packet_values, 0, sizeof(packet_values));

    subtree = proto_tree_add_subtree(tree, tvb, offset, -1, ett_kafka_response_partition, &ti, "Fetch Response Partition");

    offset = dissect_kafka_partition_id_get_value(tvb, pinfo, subtree, offset, &packet_values);

    offset = dissect_kafka_error(tvb, pinfo, subtree, offset);

    offset = dissect_kafka_offset_get_value(tvb, pinfo, subtree, offset, &packet_values);

    offset = dissect_kafka_message_set(tvb, pinfo, subtree, offset, TRUE);

    proto_item_set_len(ti, offset - start_offset);

    proto_item_append_text(ti, " (Partition-ID=%u, Offset=%" G_GINT64_MODIFIER "u)",
                           packet_values.partition_id, packet_values.offset);

    return offset;
}

static int
dissect_kafka_fetch_response_topic(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int start_offset,
                                   kafka_api_version_t api_version)
{
    proto_item *ti;
    proto_tree *subtree;
    int         offset = start_offset;
    guint32     count;

    subtree = proto_tree_add_subtree(tree, tvb, offset, -1, ett_kafka_response_topic, &ti, "Fetch Response Topic");

    offset = dissect_kafka_string(subtree, hf_kafka_topic_name, tvb, pinfo, offset, NULL, NULL);
    count = tvb_get_ntohl(tvb, offset);
    offset = dissect_kafka_array(subtree, tvb, pinfo, offset, api_version,
                                 &dissect_kafka_fetch_response_partition);

    proto_item_set_len(ti, offset - start_offset);
    proto_item_append_text(ti, " (%u partitions)", count);

    return offset;
}

static int
dissect_kafka_fetch_response(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset,
                             kafka_api_version_t api_version)
{
    if (api_version >= 1) {
        /* Throttle time */
        proto_tree_add_item(tree, hf_kafka_throttle_time, tvb, offset, 4, ENC_BIG_ENDIAN);
        offset += 4;
    }

    return dissect_kafka_array(tree, tvb, pinfo, offset, api_version, &dissect_kafka_fetch_response_topic);
}

/* PRODUCE REQUEST/RESPONSE */

static int
dissect_kafka_produce_request_partition(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset,
                                        kafka_api_version_t api_version _U_)
{
    proto_item *ti;
    proto_tree *subtree;
    kafka_packet_values_t packet_values;
    memset(&packet_values, 0, sizeof(packet_values));

    subtree = proto_tree_add_subtree(tree, tvb, offset, 14, ett_kafka_request_partition, &ti, "Produce Request Partition");

    offset = dissect_kafka_partition_id_get_value(tvb, pinfo, subtree, offset, &packet_values);

    offset = dissect_kafka_message_set(tvb, pinfo, subtree, offset, TRUE);

    proto_item_append_text(ti, " (Partition-ID=%u)", packet_values.partition_id);

    return offset;
}

static int
dissect_kafka_produce_request_topic(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int start_offset,
                                    kafka_api_version_t api_version)
{
    proto_item *ti;
    proto_tree *subtree;
    int         offset = start_offset;

    subtree = proto_tree_add_subtree(tree, tvb, offset, -1, ett_kafka_request_topic, &ti, "Produce Request Topic");

    offset = dissect_kafka_string(subtree, hf_kafka_topic_name, tvb, pinfo, offset, NULL, NULL);
    offset = dissect_kafka_array(subtree, tvb, pinfo, offset, api_version,
                                 &dissect_kafka_produce_request_partition);

    proto_item_set_len(ti, offset - start_offset);

    return offset;
}

static int
dissect_kafka_produce_request(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset,
                              kafka_api_version_t api_version)
{
    proto_tree_add_item(tree, hf_kafka_required_acks, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    proto_tree_add_item(tree, hf_kafka_timeout, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;

    offset = dissect_kafka_array(tree, tvb, pinfo, offset, api_version,
                                 &dissect_kafka_produce_request_topic);

    return offset;
}

static int
dissect_kafka_produce_response_partition(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset,
                                         kafka_api_version_t api_version _U_)
{
    proto_item *ti;
    proto_tree *subtree;
    kafka_packet_values_t packet_values;
    memset(&packet_values, 0, sizeof(packet_values));

    subtree = proto_tree_add_subtree(tree, tvb, offset, 14, ett_kafka_response_partition, &ti, "Produce Response Partition");

    offset = dissect_kafka_partition_id_get_value(tvb, pinfo, subtree, offset, &packet_values);

    offset = dissect_kafka_error(tvb, pinfo, subtree, offset);

    offset = dissect_kafka_offset_get_value(tvb, pinfo, subtree, offset, &packet_values);

    if (api_version >= 2) {
        offset = dissect_kafka_offset_time(tvb, pinfo, subtree, offset, api_version);
    }

    proto_item_append_text(ti, " (Partition-ID=%u, Offset=%" G_GINT64_MODIFIER "u)",
                           packet_values.partition_id, packet_values.offset);

    return offset;
}

static int
dissect_kafka_produce_response_topic(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int start_offset,
                                     kafka_api_version_t api_version)
{
    proto_item *ti;
    proto_tree *subtree;
    int         offset = start_offset;

    subtree = proto_tree_add_subtree(tree, tvb, offset, -1, ett_kafka_response_topic, &ti, "Produce Response Topic");

    offset = dissect_kafka_string(subtree, hf_kafka_topic_name, tvb, pinfo, offset, NULL, NULL);
    offset = dissect_kafka_array(subtree, tvb, pinfo, offset, api_version,
                                 &dissect_kafka_produce_response_partition);

    proto_item_set_len(ti, offset - start_offset);

    return offset;
}

static int
dissect_kafka_produce_response(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset,
                               kafka_api_version_t api_version)
{
    offset = dissect_kafka_array(tree, tvb, pinfo, offset, api_version, &dissect_kafka_produce_response_topic);

    if (api_version >= 1) {
        /* Throttle time */
        proto_tree_add_item(tree, hf_kafka_throttle_time, tvb, offset, 4, ENC_BIG_ENDIAN);
        offset += 4;
    }

    return offset;
}

/* OFFSETS REQUEST/RESPONSE */

static int
dissect_kafka_offsets_request_partition(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                                        int start_offset, kafka_api_version_t api_version)
{
    proto_item *ti;
    proto_tree *subtree;
    int         offset = start_offset;

    subtree = proto_tree_add_subtree(tree, tvb, offset, -1, ett_kafka_request_partition, &ti, "Offset Request Partition");

    offset = dissect_kafka_partition_id(tvb, pinfo, subtree, offset, api_version);

    offset = dissect_kafka_offset_time(tvb, pinfo, subtree, offset, api_version);

    if (api_version == 0) {
        proto_tree_add_item(subtree, hf_kafka_max_offsets, tvb, offset, 4, ENC_BIG_ENDIAN);
        offset += 4;
    }

    proto_item_set_len(ti, offset - start_offset);

    return offset;
}

static int
dissect_kafka_offsets_request_topic(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int start_offset,
                                    kafka_api_version_t api_version)
{
    proto_item *ti;
    proto_tree *subtree;
    int         offset = start_offset;

    subtree = proto_tree_add_subtree(tree, tvb, offset, -1, ett_kafka_request_topic, &ti, "Offset Request Topic");

    offset = dissect_kafka_string(subtree, hf_kafka_topic_name, tvb, pinfo, offset, NULL, NULL);
    offset = dissect_kafka_array(subtree, tvb, pinfo, offset, api_version,
                                 &dissect_kafka_offsets_request_partition);

    proto_item_set_len(ti, offset - start_offset);

    return offset;
}

static int
dissect_kafka_offsets_request(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset,
                              kafka_api_version_t api_version)
{
    proto_tree_add_item(tree, hf_kafka_replica, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;

    offset = dissect_kafka_array(tree, tvb, pinfo, offset, api_version, &dissect_kafka_offsets_request_topic);

    return offset;
}

static int
dissect_kafka_offsets_response_partition(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                                         int start_offset, kafka_api_version_t api_version)
{
    proto_item *ti;
    proto_tree *subtree;
    int         offset = start_offset;

    subtree = proto_tree_add_subtree(tree, tvb, offset, -1, ett_kafka_response_partition, &ti, "Offset Response Partition");

    offset = dissect_kafka_partition_id(tvb, pinfo, subtree, offset, api_version);

    offset = dissect_kafka_error(tvb, pinfo, subtree, offset);

    if (api_version == 0) {
        offset = dissect_kafka_array(subtree, tvb, pinfo, offset, api_version, &dissect_kafka_offset);
    }
    else if (api_version >= 1) {
        offset = dissect_kafka_offset_time(tvb, pinfo, subtree, offset, api_version);

        offset = dissect_kafka_offset(tvb, pinfo, subtree, offset, api_version);
    }

    proto_item_set_len(ti, offset - start_offset);

    return offset;
}

static int
dissect_kafka_offsets_response_topic(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int start_offset,
                                     kafka_api_version_t api_version)
{
    proto_item *ti;
    proto_tree *subtree;
    int         offset = start_offset;

    subtree = proto_tree_add_subtree(tree, tvb, offset, -1, ett_kafka_response_topic, &ti, "Offset Response Topic");

    offset = dissect_kafka_string(subtree, hf_kafka_topic_name, tvb, pinfo, offset, NULL, NULL);
    offset = dissect_kafka_array(subtree, tvb, pinfo, offset, api_version,
                                 &dissect_kafka_offsets_response_partition);

    proto_item_set_len(ti, offset - start_offset);

    return offset;
}

static int
dissect_kafka_offsets_response(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset,
                               kafka_api_version_t api_version)
{
    return dissect_kafka_array(tree, tvb, pinfo, offset, api_version, &dissect_kafka_offsets_response_topic);
}

/* API_VERSIONS REQUEST/RESPONSE */

static int
dissect_kafka_api_versions_response_api_versions(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree,
                                                 int start_offset, kafka_api_version_t api_version _U_)
{
    proto_item *ti;
    proto_tree *subtree;
    int         offset = start_offset;

    subtree = proto_tree_add_subtree(tree, tvb, offset, -1, ett_kafka_api_versions, &ti,
                                     "API Versions");

    proto_tree_add_item(subtree, hf_kafka_api_versions_api_key, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    proto_tree_add_item(subtree, hf_kafka_api_versions_min_version, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    proto_tree_add_item(subtree, hf_kafka_api_versions_max_version, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    proto_item_set_len(ti, offset - start_offset);

    return offset;
}

static int
dissect_kafka_api_versions_response(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset,
                                    kafka_api_version_t api_version)
{
    offset = dissect_kafka_error(tvb, pinfo, tree, offset);
    return dissect_kafka_array(tree, tvb, pinfo, offset, api_version,
                               &dissect_kafka_api_versions_response_api_versions);
}

/* MAIN */

static int
dissect_kafka(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
    proto_item             *root_ti, *ti;
    proto_tree             *kafka_tree;
    int                     offset  = 0;
    kafka_query_response_t *matcher = NULL;
    conversation_t         *conversation;
    wmem_queue_t           *match_queue;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "Kafka");
    col_clear(pinfo->cinfo, COL_INFO);

    root_ti = proto_tree_add_item(tree, proto_kafka, tvb, 0, -1, ENC_NA);

    kafka_tree = proto_item_add_subtree(root_ti, ett_kafka);

    proto_tree_add_item(kafka_tree, hf_kafka_len, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;

    conversation = find_or_create_conversation(pinfo);
    /* Create match_queue for this conversation */
    match_queue  = (wmem_queue_t *) conversation_get_proto_data(conversation, proto_kafka);
    if (match_queue == NULL) {
        match_queue = wmem_queue_new(wmem_file_scope());
        conversation_add_proto_data(conversation, proto_kafka, match_queue);
    }

    if (PINFO_FD_VISITED(pinfo)) {
        matcher = (kafka_query_response_t *) p_get_proto_data(wmem_file_scope(), pinfo, proto_kafka, 0);
    }

    if (value_is_in_range(current_kafka_tcp_range, pinfo->destport)) {
        /* Request (as directed towards server port) */
        if (matcher == NULL) {
            matcher = wmem_new(wmem_file_scope(), kafka_query_response_t);

            matcher->api_key        = tvb_get_ntohs(tvb, offset);
            matcher->api_version    = tvb_get_ntohs(tvb, offset+2);
            matcher->request_frame  = pinfo->num;
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

        col_add_fstr(pinfo->cinfo, COL_INFO, "Kafka %s v%d Request",
                     val_to_str_const(matcher->api_key, kafka_apis, "Unknown"),
                     matcher->api_version);
        /* Also add to protocol root */
        proto_item_append_text(root_ti, " (%s v%d Request)",
                               val_to_str_const(matcher->api_key, kafka_apis, "Unknown"),
                               matcher->api_version);

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

        offset = dissect_kafka_string(kafka_tree, hf_kafka_client_id, tvb, pinfo, offset, NULL, NULL);

        switch (matcher->api_key) {
            /* TODO: decode other request types */
            case KAFKA_PRODUCE:
                /* Produce requests may need delayed queueing, see the more
                 * detailed comment above. */
                if (tvb_get_ntohs(tvb, offset) != 0 && !PINFO_FD_VISITED(pinfo)) {
                    wmem_queue_push(match_queue, matcher);
                }
                /*offset =*/ dissect_kafka_produce_request(tvb, pinfo, kafka_tree, offset, matcher->api_version);
                break;
            case KAFKA_OFFSET_FETCH:
                /*offset =*/ dissect_kafka_offset_fetch_request(tvb, pinfo, kafka_tree, offset, matcher->api_version);
                break;
            case KAFKA_METADATA:
                /*offset =*/ dissect_kafka_metadata_request(tvb, pinfo, kafka_tree, offset, matcher->api_version);
                break;
            case KAFKA_FETCH:
                /*offset =*/ dissect_kafka_fetch_request(tvb, pinfo, kafka_tree, offset, matcher->api_version);
                break;
            case KAFKA_OFFSETS:
                /*offset =*/ dissect_kafka_offsets_request(tvb, pinfo, kafka_tree, offset, matcher->api_version);
                break;
            case KAFKA_API_VERSIONS:
                break;
        }
    }
    else {
        /* Response */

        proto_tree_add_item(kafka_tree, hf_kafka_correlation_id, tvb, offset, 4, ENC_BIG_ENDIAN);
        offset += 4;

        if (matcher == NULL) {
            if (wmem_queue_count(match_queue) > 0) {
                matcher = (kafka_query_response_t *) wmem_queue_peek(match_queue);
            }
            if (matcher == NULL || matcher->request_frame >= pinfo->num) {
                col_set_str(pinfo->cinfo, COL_INFO, "Kafka Response (Unknown API, Missing Request)");
                /* TODO: expert info, don't have request, can't dissect */
                return tvb_captured_length(tvb);
            }

            wmem_queue_pop(match_queue);

            matcher->response_frame = pinfo->num;
            matcher->response_found = TRUE;

            p_add_proto_data(wmem_file_scope(), pinfo, proto_kafka, 0, matcher);
        }

        col_add_fstr(pinfo->cinfo, COL_INFO, "Kafka %s v%d Response",
                     val_to_str_const(matcher->api_key, kafka_apis, "Unknown"),
                     matcher->api_version);
        /* Also add to protocol root */
        proto_item_append_text(root_ti, " (%s v%d Response)",
                               val_to_str_const(matcher->api_key, kafka_apis, "Unknown"),
                               matcher->api_version);


        /* Show request frame */
        ti = proto_tree_add_uint(kafka_tree, hf_kafka_request_frame, tvb,
                0, 0, matcher->request_frame);
        PROTO_ITEM_SET_GENERATED(ti);

        /* Show api key (message type) */
        ti = proto_tree_add_int(kafka_tree, hf_kafka_response_api_key, tvb,
                0, 0, matcher->api_key);
        PROTO_ITEM_SET_GENERATED(ti);

        /* Also show api version from request */
        ti = proto_tree_add_int(kafka_tree, hf_kafka_response_api_version, tvb,
                0, 0, matcher->api_version);
        PROTO_ITEM_SET_GENERATED(ti);


        switch (matcher->api_key) {
            /* TODO: decode other response types */
            case KAFKA_PRODUCE:
                /*offset =*/ dissect_kafka_produce_response(tvb, pinfo, kafka_tree, offset, matcher->api_version);
                break;
            case KAFKA_OFFSET_FETCH:
                /*offset =*/ dissect_kafka_offset_fetch_response(tvb, pinfo, kafka_tree, offset, matcher->api_version);
                break;
            case KAFKA_METADATA:
                /*offset =*/ dissect_kafka_metadata_response(tvb, pinfo, kafka_tree, offset, matcher->api_version);
                break;
            case KAFKA_FETCH:
                /*offset =*/ dissect_kafka_fetch_response(tvb, pinfo, kafka_tree, offset, matcher->api_version);
                break;
            case KAFKA_OFFSETS:
                /*offset =*/ dissect_kafka_offsets_response(tvb, pinfo, kafka_tree, offset, matcher->api_version);
                break;
            case KAFKA_API_VERSIONS:
                /*offset =*/ dissect_kafka_api_versions_response(tvb, pinfo, kafka_tree, offset, matcher->api_version);
                break;
        }

    }

    return tvb_captured_length(tvb);
}

static int
dissect_kafka_tcp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
        void *data)
{
    tcp_dissect_pdus(tvb, pinfo, tree, TRUE, 4,
            get_kafka_pdu_len, dissect_kafka, data);

    return tvb_captured_length(tvb);
}


static void
apply_kafka_prefs(void) {
    pref_t *kafka_ports = prefs_find_preference(prefs_find_module("kafka"), "tcp.port");

    current_kafka_tcp_range = range_copy(*kafka_ports->varp.range);
}

void
proto_register_kafka(void)
{
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
        { &hf_kafka_offset_time,
            { "Time", "kafka.offset_time",
               FT_INT64, BASE_DEC, 0, 0,
               NULL, HFILL }
        },
        { &hf_kafka_max_offsets,
            { "Max Offsets", "kafka.max_offsets",
               FT_INT32, BASE_DEC, 0, 0,
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
            { "API Version", "kafka.request.version",
               FT_INT16, BASE_DEC, 0, 0,
              "Request API Version.", HFILL }
        },
        { &hf_kafka_response_api_version,
            { "API Version", "kafka.response.version",
               FT_INT16, BASE_DEC, 0, 0,
              "Response API Version.", HFILL }
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
               FT_UINT8, BASE_DEC, VALS(kafka_codecs), 0x03,
               NULL, HFILL }
        },
        { &hf_kafka_message_timestamp,
            { "Timestamp", "kafka.message_timestamp",
               FT_ABSOLUTE_TIME, ABSOLUTE_TIME_UTC, NULL, 0,
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
               FT_FRAMENUM, BASE_NONE, FRAMENUM_TYPE(FT_FRAMENUM_REQUEST), 0,
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
        { &hf_kafka_broker_rack,
            { "Rack", "kafka.rack",
               FT_STRING, BASE_NONE, 0, 0,
               NULL, HFILL }
        },
        { &hf_kafka_cluster_id,
            { "Cluster ID", "kafka.cluster_id",
               FT_STRING, BASE_NONE, 0, 0,
               NULL, HFILL }
        },
        { &hf_kafka_controller_id,
            { "Controller ID", "kafka.node_id",
               FT_INT32, BASE_DEC, 0, 0,
               NULL, HFILL }
        },
        { &hf_kafka_is_internal,
            { "Is Internal", "kafka.is_internal",
               FT_BOOLEAN, BASE_NONE, 0, 0,
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
        { &hf_kafka_throttle_time,
            { "Throttle time", "kafka.throttle_time",
               FT_INT32, BASE_DEC, 0, 0,
               "Duration in milliseconds for which the request was throttled"
                   " due to quota violation."
                   " (Zero if the request did not violate any quota.)",
               HFILL }
        },
        { &hf_kafka_response_frame,
            { "Response Frame", "kafka.reponse_frame",
               FT_FRAMENUM, BASE_NONE, FRAMENUM_TYPE(FT_FRAMENUM_RESPONSE), 0,
               NULL, HFILL }
        },
        { &hf_kafka_api_versions_api_key,
            { "API Key", "kafka.api_versions.api_key",
               FT_INT16, BASE_DEC, VALS(kafka_apis), 0,
              "API Key.", HFILL }
        },
        { &hf_kafka_api_versions_min_version,
            { "Min Version", "kafka.api_versions.min_version",
               FT_INT16, BASE_DEC, 0, 0,
              "Minimal version which supports api key.", HFILL }
        },
        { &hf_kafka_api_versions_max_version,
            { "Max Version", "kafka.api_versions.max_version",
              FT_INT16, BASE_DEC, 0, 0,
              "Maximal version which supports api key.", HFILL }
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
        &ett_kafka_response_partition,
        &ett_kafka_api_versions
    };

    static ei_register_info ei[] = {
        { &ei_kafka_message_decompress, { "kafka.decompress_failed", PI_UNDECODED, PI_WARN, "Failed to decompress message", EXPFILL }},
        { &ei_kafka_bad_string_length, { "kafka.bad_string_length", PI_MALFORMED, PI_WARN, "Invalid string length field", EXPFILL }},
        { &ei_kafka_bad_bytes_length, { "kafka.bad_bytes_length", PI_MALFORMED, PI_WARN, "Invalid byte length field", EXPFILL }},
    };

    expert_module_t* expert_kafka;

    proto_kafka = proto_register_protocol("Kafka", "Kafka", "kafka");

    proto_register_field_array(proto_kafka, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
    expert_kafka = expert_register_protocol(proto_kafka);
    expert_register_field_array(expert_kafka, ei, array_length(ei));

    prefs_register_protocol(proto_kafka, apply_kafka_prefs);
}

void
proto_reg_handoff_kafka(void)
{
    dissector_handle_t kafka_handle;

    kafka_handle = create_dissector_handle(dissect_kafka_tcp, proto_kafka);

    /* Replace range of ports with current */
    dissector_add_uint_range_with_preference("tcp.port", "", kafka_handle);
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
