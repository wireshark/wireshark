/* packet-kafka.c
 * Routines for Apache Kafka Protocol dissection (version 0.8 - 2.5)
 * Copyright 2013, Evan Huus <eapache@gmail.com>
 * Update from Kafka 0.10.1.0 to 2.5 by Piotr Smolinski <piotr.smolinski@confluent.io>
 *
 * https://cwiki.apache.org/confluence/display/KAFKA/A+Guide+To+The+Kafka+Protocol
 * https://kafka.apache.org/protocol.html
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <epan/packet.h>
#include <epan/expert.h>
#include <epan/prefs.h>
#include <epan/proto_data.h>
#ifdef HAVE_SNAPPY
#include <snappy-c.h>
#endif
#ifdef HAVE_LZ4FRAME_H
#include <lz4.h>
#include <lz4frame.h>
#endif
#include "packet-tcp.h"
#include "packet-tls.h"

void proto_register_kafka(void);
void proto_reg_handoff_kafka(void);

static int proto_kafka;

static int hf_kafka_len;
static int hf_kafka_api_key;
static int hf_kafka_api_version;
static int hf_kafka_request_api_key;
static int hf_kafka_response_api_key;
static int hf_kafka_request_api_version;
static int hf_kafka_response_api_version;
static int hf_kafka_correlation_id;
static int hf_kafka_client_id;
static int hf_kafka_client_host;
static int hf_kafka_required_acks;
static int hf_kafka_timeout;
static int hf_kafka_topic_name;
static int hf_kafka_topic_id;
static int hf_kafka_transactional_id;
static int hf_kafka_transaction_result;
static int hf_kafka_transaction_timeout;
static int hf_kafka_partition_id;
static int hf_kafka_replica;
static int hf_kafka_replication_factor;
static int hf_kafka_isr;
static int hf_kafka_offline;
static int hf_kafka_last_stable_offset;
static int hf_kafka_log_start_offset;
static int hf_kafka_first_offset;
static int hf_kafka_producer_id;
static int hf_kafka_producer_epoch;
static int hf_kafka_message_size;
static int hf_kafka_message_crc;
static int hf_kafka_message_magic;
static int hf_kafka_message_codec;
static int hf_kafka_message_timestamp_type;
static int hf_kafka_message_timestamp;
static int hf_kafka_batch_crc;
static int hf_kafka_batch_codec;
static int hf_kafka_batch_timestamp_type;
static int hf_kafka_batch_transactional;
static int hf_kafka_batch_control_batch;
static int hf_kafka_batch_last_offset_delta;
static int hf_kafka_batch_first_timestamp;
static int hf_kafka_batch_last_timestamp;
static int hf_kafka_batch_base_sequence;
static int hf_kafka_batch_size;
static int hf_kafka_batch_index;
static int hf_kafka_batch_index_error_message;
static int hf_kafka_message_key;
static int hf_kafka_message_value;
static int hf_kafka_message_compression_reduction;
static int hf_kafka_truncated_content;
static int hf_kafka_request_frame;
static int hf_kafka_response_frame;
static int hf_kafka_consumer_group;
static int hf_kafka_consumer_group_instance;
static int hf_kafka_coordinator_key;
static int hf_kafka_coordinator_type;
static int hf_kafka_group_state;
static int hf_kafka_offset;
static int hf_kafka_offset_time;
static int hf_kafka_max_offsets;
static int hf_kafka_metadata;
static int hf_kafka_error;
static int hf_kafka_error_message;
static int hf_kafka_broker_nodeid;
static int hf_kafka_broker_epoch;
static int hf_kafka_broker_host;
static int hf_kafka_listener_name;
static int hf_kafka_broker_port;
static int hf_kafka_rack;
static int hf_kafka_broker_security_protocol_type;
static int hf_kafka_cluster_id;
static int hf_kafka_controller_id;
static int hf_kafka_controller_epoch;
static int hf_kafka_delete_partitions;
static int hf_kafka_leader_id;
static int hf_kafka_group_leader_id;
static int hf_kafka_leader_epoch;
static int hf_kafka_current_leader_epoch;
static int hf_kafka_is_internal;
static int hf_kafka_isolation_level;
static int hf_kafka_min_bytes;
static int hf_kafka_max_bytes;
static int hf_kafka_max_wait_time;
static int hf_kafka_throttle_time;
static int hf_kafka_api_versions_api_key;
static int hf_kafka_api_versions_min_version;
static int hf_kafka_api_versions_max_version;
static int hf_kafka_session_timeout;
static int hf_kafka_rebalance_timeout;
static int hf_kafka_member_id;
static int hf_kafka_protocol_type;
static int hf_kafka_protocol_name;
static int hf_kafka_protocol_metadata;
static int hf_kafka_member_metadata;
static int hf_kafka_generation_id;
static int hf_kafka_member_assignment;
static int hf_kafka_sasl_mechanism;
static int hf_kafka_num_partitions;
static int hf_kafka_zk_version;
static int hf_kafka_is_new_replica;
static int hf_kafka_leader_recovery_state;
static int hf_kafka_config_key;
static int hf_kafka_config_value;
static int hf_kafka_commit_timestamp;
static int hf_kafka_retention_time;
static int hf_kafka_forgotten_topic_name;
static int hf_kafka_forgotten_topic_id;
static int hf_kafka_forgotten_topic_partition;
static int hf_kafka_fetch_session_id;
static int hf_kafka_fetch_session_epoch;
static int hf_kafka_require_stable_offset;
static int hf_kafka_record_header_key;
static int hf_kafka_record_header_value;
static int hf_kafka_record_attributes;
static int hf_kafka_allow_auto_topic_creation;
static int hf_kafka_validate_only;
static int hf_kafka_coordinator_epoch;
static int hf_kafka_sasl_auth_bytes;
static int hf_kafka_session_lifetime_ms;
static int hf_kafka_acl_resource_type;
static int hf_kafka_acl_resource_name;
static int hf_kafka_acl_resource_pattern_type;
static int hf_kafka_acl_principal;
static int hf_kafka_acl_host;
static int hf_kafka_acl_operation;
static int hf_kafka_acl_permission_type;
static int hf_kafka_config_resource_type;
static int hf_kafka_config_resource_name;
static int hf_kafka_config_include_synonyms;
static int hf_kafka_config_include_documentation;
static int hf_kafka_config_source;
static int hf_kafka_config_readonly;
static int hf_kafka_config_default;
static int hf_kafka_config_sensitive;
static int hf_kafka_config_data_type;
static int hf_kafka_config_documentation;
static int hf_kafka_config_operation;
static int hf_kafka_log_dir;
static int hf_kafka_segment_size;
static int hf_kafka_offset_lag;
static int hf_kafka_future;
static int hf_kafka_partition_count;
static int hf_kafka_token_max_life_time;
static int hf_kafka_token_renew_time;
static int hf_kafka_token_expiry_time;
static int hf_kafka_token_principal_type;
static int hf_kafka_token_principal_name;
static int hf_kafka_token_issue_timestamp;
static int hf_kafka_token_expiry_timestamp;
static int hf_kafka_token_max_timestamp;
static int hf_kafka_token_id;
static int hf_kafka_token_hmac;
static int hf_kafka_include_cluster_authorized_ops;
static int hf_kafka_include_topic_authorized_ops;
static int hf_kafka_include_group_authorized_ops;
static int hf_kafka_cluster_authorized_ops;
static int hf_kafka_topic_authorized_ops;
static int hf_kafka_group_authorized_ops;
static int hf_kafka_election_type;
static int hf_kafka_tagged_field_tag;
static int hf_kafka_tagged_field_data;
static int hf_kafka_client_software_name;
static int hf_kafka_client_software_version;
static int hf_kafka_is_kraft_controller;
static int hf_kafka_topic_inclusion_type;
static int hf_kafka_delete_partition;
static int hf_kafka_join_reason;
static int hf_kafka_leave_reason;
static int hf_kafka_skip_assignment;
static int hf_kafka_producer_id_start;
static int hf_kafka_producer_id_len;
static int hf_kafka_group_id;
static int hf_kafka_member_epoch;
static int hf_kafka_endpoint_type;
static int hf_kafka_last_fetched_epoch;

static int ett_kafka;
static int ett_kafka_batch;
static int ett_kafka_message;
static int ett_kafka_message_set;
static int ett_kafka_replicas;
static int ett_kafka_isrs;
static int ett_kafka_offline;
static int ett_kafka_broker;
static int ett_kafka_brokers;
static int ett_kafka_broker_end_point;
static int ett_kafka_markers;
static int ett_kafka_marker;
static int ett_kafka_topics;
static int ett_kafka_topic;
static int ett_kafka_partitions;
static int ett_kafka_partition;
static int ett_kafka_api_version;
static int ett_kafka_group_protocols;
static int ett_kafka_group_protocol;
static int ett_kafka_group_members;
static int ett_kafka_group_member;
static int ett_kafka_group_assignments;
static int ett_kafka_group_assignment;
static int ett_kafka_groups;
static int ett_kafka_group;
static int ett_kafka_sasl_enabled_mechanisms;
static int ett_kafka_replica_assignment;
static int ett_kafka_configs;
static int ett_kafka_config;
static int ett_kafka_request_forgotten_topic;
static int ett_kafka_record;
static int ett_kafka_record_headers;
static int ett_kafka_record_headers_header;
static int ett_kafka_aborted_transactions;
static int ett_kafka_aborted_transaction;
static int ett_kafka_resources;
static int ett_kafka_resource;
static int ett_kafka_acls;
static int ett_kafka_acl;
static int ett_kafka_acl_creations;
static int ett_kafka_acl_creation;
static int ett_kafka_acl_filters;
static int ett_kafka_acl_filter;
static int ett_kafka_acl_filter_matches;
static int ett_kafka_acl_filter_match;
static int ett_kafka_config_synonyms;
static int ett_kafka_config_synonym;
static int ett_kafka_config_entries;
static int ett_kafka_config_entry;
static int ett_kafka_log_dirs;
static int ett_kafka_log_dir;
static int ett_kafka_renewers;
static int ett_kafka_renewer;
static int ett_kafka_owners;
static int ett_kafka_owner;
static int ett_kafka_tokens;
static int ett_kafka_token;
/* in Kafka 2.5 these structures have been added, but not yet used */
static int ett_kafka_tagged_fields;
static int ett_kafka_tagged_field;
static int ett_kafka_record_errors;
static int ett_kafka_record_error;

static expert_field ei_kafka_request_missing;
static expert_field ei_kafka_unknown_api_key;
static expert_field ei_kafka_unsupported_api_version;
static expert_field ei_kafka_assumed_api_version;
static expert_field ei_kafka_bad_string_length;
static expert_field ei_kafka_bad_bytes_length;
static expert_field ei_kafka_bad_array_length;
static expert_field ei_kafka_bad_record_length;
static expert_field ei_kafka_bad_varint;
static expert_field ei_kafka_bad_message_set_length;
static expert_field ei_kafka_bad_decompression_length;
static expert_field ei_kafka_zero_decompression_length;
static expert_field ei_kafka_unknown_message_magic;
static expert_field ei_kafka_pdu_length_mismatch;
static expert_field ei_kafka_zero_field_length;

typedef int16_t kafka_api_key_t;
typedef int16_t kafka_api_version_t;
typedef int16_t kafka_error_t;
typedef int32_t kafka_partition_t;
typedef int64_t kafka_offset_t;

typedef struct _kafka_api_info_t {
    kafka_api_key_t api_key;
    const char *name;
    /* If api key is not supported then set min_version and max_version to -1 */
    kafka_api_version_t min_version;
    kafka_api_version_t max_version;
    /* Added in Kafka 2.4. Protocol messages are upgraded gradually. */
    kafka_api_version_t flexible_since;
} kafka_api_info_t;

#define KAFKA_TCP_DEFAULT_RANGE     "9092"

#define KAFKA_PRODUCE                             0
#define KAFKA_FETCH                               1
#define KAFKA_OFFSETS                             2
#define KAFKA_METADATA                            3
#define KAFKA_LEADER_AND_ISR                      4
#define KAFKA_STOP_REPLICA                        5
#define KAFKA_UPDATE_METADATA                     6
#define KAFKA_CONTROLLED_SHUTDOWN                 7
#define KAFKA_OFFSET_COMMIT                       8
#define KAFKA_OFFSET_FETCH                        9
#define KAFKA_FIND_COORDINATOR                   10
#define KAFKA_JOIN_GROUP                         11
#define KAFKA_HEARTBEAT                          12
#define KAFKA_LEAVE_GROUP                        13
#define KAFKA_SYNC_GROUP                         14
#define KAFKA_DESCRIBE_GROUPS                    15
#define KAFKA_LIST_GROUPS                        16
#define KAFKA_SASL_HANDSHAKE                     17
#define KAFKA_API_VERSIONS                       18
#define KAFKA_CREATE_TOPICS                      19
#define KAFKA_DELETE_TOPICS                      20
#define KAFKA_DELETE_RECORDS                     21
#define KAFKA_INIT_PRODUCER_ID                   22
#define KAFKA_OFFSET_FOR_LEADER_EPOCH            23
#define KAFKA_ADD_PARTITIONS_TO_TXN              24
#define KAFKA_ADD_OFFSETS_TO_TXN                 25
#define KAFKA_END_TXN                            26
#define KAFKA_WRITE_TXN_MARKERS                  27
#define KAFKA_TXN_OFFSET_COMMIT                  28
#define KAFKA_DESCRIBE_ACLS                      29
#define KAFKA_CREATE_ACLS                        30
#define KAFKA_DELETE_ACLS                        31
#define KAFKA_DESCRIBE_CONFIGS                   32
#define KAFKA_ALTER_CONFIGS                      33
#define KAFKA_ALTER_REPLICA_LOG_DIRS             34
#define KAFKA_DESCRIBE_LOG_DIRS                  35
#define KAFKA_SASL_AUTHENTICATE                  36
#define KAFKA_CREATE_PARTITIONS                  37
#define KAFKA_CREATE_DELEGATION_TOKEN            38
#define KAFKA_RENEW_DELEGATION_TOKEN             39
#define KAFKA_EXPIRE_DELEGATION_TOKEN            40
#define KAFKA_DESCRIBE_DELEGATION_TOKEN          41
#define KAFKA_DELETE_GROUPS                      42
#define KAFKA_ELECT_LEADERS                      43
#define KAFKA_INC_ALTER_CONFIGS                  44
#define KAFKA_ALTER_PARTITION_REASSIGNMENTS      45
#define KAFKA_LIST_PARTITION_REASSIGNMENTS       46
#define KAFKA_OFFSET_DELETE                      47
#define KAFKA_DESCRIBE_CLIENT_QUOTAS             48
#define KAFKA_ALTER_CLIENT_QUOTAS                49
#define KAFKA_DESCRIBE_USER_SCRAM_CREDENTIALS    50
#define KAFKA_ALTER_USER_SCRAM_CREDENTIALS       51
#define KAFKA_DESCRIBE_QUORUM                    55
#define KAFKA_ALTER_PARTITION                    56
#define KAFKA_UPDATE_FEATURES                    57
#define KAFKA_ENVELOPE                           58
#define KAFKA_DESCRIBE_CLUSTER                   60
#define KAFKA_DESCRIBE_PRODUCERS                 61
#define KAFKA_UNREGISTER_BROKER                  64
#define KAFKA_DESCRIBE_TRANSACTIONS              65
#define KAFKA_LIST_TRANSACTIONS                  66
#define KAFKA_ALLOCATE_PRODUCER_IDS              67
#define KAFKA_CONSUMER_GROUP_HEARTBEAT           68
#define KAFKA_CONSUMER_GROUP_DESCRIBE            69
#define KAFKA_GET_TELEMETRY_SUBSCRIPTIONS        71
#define KAFKA_PUSH_TELEMETRY                     72
#define KAFKA_LIST_CLIENT_METRICS_RESOURCES      74

/*
 * Check for message changes here:
 * https://github.com/apache/kafka/tree/trunk/clients/src/main/resources/common/message
 * The values are:
 * - api key
 * - min supported version
 * - max supported version
 * - flexible since (new in 2.4) - drives if string fields are prefixed by short or varint (unsigned)
 * Flexible request header is 2 and response header id 1.
 * Note that request header version is hardcoded to 0 for ControlledShutdown v.0 and
 * response header version for ApiVersions is always 0.
 */
static const kafka_api_info_t kafka_apis[] = {
    { KAFKA_PRODUCE,                       "Produce",
      0, 11, 9 },
    { KAFKA_FETCH,                         "Fetch",
      0, 16, 12 },
    { KAFKA_OFFSETS,                       "Offsets",
      0, 8, 6 },
    { KAFKA_METADATA,                      "Metadata",
      0, 12, 9 },
    { KAFKA_LEADER_AND_ISR,                "LeaderAndIsr",
      0, 7, 4 },
    { KAFKA_STOP_REPLICA,                  "StopReplica",
      0, 4, 2 },
    { KAFKA_UPDATE_METADATA,               "UpdateMetadata",
      0, 8, 6 },
    { KAFKA_CONTROLLED_SHUTDOWN,           "ControlledShutdown",
      0, 3, 3 },
    { KAFKA_OFFSET_COMMIT,                 "OffsetCommit",
      0, 8, 8 },
    { KAFKA_OFFSET_FETCH,                  "OffsetFetch",
      0, 9, 6 },
    { KAFKA_FIND_COORDINATOR,              "FindCoordinator",
      0, 5, 3 },
    { KAFKA_JOIN_GROUP,                    "JoinGroup",
      0, 9, 6 },
    { KAFKA_HEARTBEAT,                     "Heartbeat",
      0, 4, 4 },
    { KAFKA_LEAVE_GROUP,                   "LeaveGroup",
      0, 5, 4 },
    { KAFKA_SYNC_GROUP,                    "SyncGroup",
      0, 5, 4 },
    { KAFKA_DESCRIBE_GROUPS,               "DescribeGroups",
      0, 5, 5 },
    { KAFKA_LIST_GROUPS,                   "ListGroups",
      0, 3, 3 },
    { KAFKA_SASL_HANDSHAKE,                "SaslHandshake",
      0, 1, -1 },
    { KAFKA_API_VERSIONS,                  "ApiVersions",
      0, 3, 3 },
    { KAFKA_CREATE_TOPICS,                 "CreateTopics",
      0, 7, 5 },
    { KAFKA_DELETE_TOPICS,                 "DeleteTopics",
      0, 6, 4 },
    { KAFKA_DELETE_RECORDS,                "DeleteRecords",
      0, 1, -1 },
    { KAFKA_INIT_PRODUCER_ID,              "InitProducerId",
      0, 5, 2 },
    { KAFKA_OFFSET_FOR_LEADER_EPOCH,       "OffsetForLeaderEpoch",
      0, 3, -1 },
    { KAFKA_ADD_PARTITIONS_TO_TXN,         "AddPartitionsToTxn",
      0, 1, -1 },
    { KAFKA_ADD_OFFSETS_TO_TXN,            "AddOffsetsToTxn",
      0, 1, -1 },
    { KAFKA_END_TXN,                       "EndTxn",
      0, 1, -1 },
    { KAFKA_WRITE_TXN_MARKERS,             "WriteTxnMarkers",
      0, 0, -1 },
    { KAFKA_TXN_OFFSET_COMMIT,             "TxnOffsetCommit",
      0, 3, 3 },
    { KAFKA_DESCRIBE_ACLS,                 "DescribeAcls",
      0, 2, 2 },
    { KAFKA_CREATE_ACLS,                   "CreateAcls",
      0, 2, 2 },
    { KAFKA_DELETE_ACLS,                   "DeleteAcls",
      0, 2, 2 },
    { KAFKA_DESCRIBE_CONFIGS,              "DescribeConfigs",
      0, 4, 4 },
    { KAFKA_ALTER_CONFIGS,                 "AlterConfigs",
      0, 1, -1 },
    { KAFKA_ALTER_REPLICA_LOG_DIRS,        "AlterReplicaLogDirs",
      0, 1, -1 },
    { KAFKA_DESCRIBE_LOG_DIRS,             "DescribeLogDirs",
      0, 1, -1 },
    { KAFKA_SASL_AUTHENTICATE,             "SaslAuthenticate",
      0, 2, 2 },
    { KAFKA_CREATE_PARTITIONS,             "CreatePartitions",
      0, 2, 2 },
    { KAFKA_CREATE_DELEGATION_TOKEN,       "CreateDelegationToken",
      0, 2, 2 },
    { KAFKA_RENEW_DELEGATION_TOKEN,        "RenewDelegationToken",
      0, 2, 2 },
    { KAFKA_EXPIRE_DELEGATION_TOKEN,       "ExpireDelegationToken",
      0, 2, 2 },
    { KAFKA_DESCRIBE_DELEGATION_TOKEN,     "DescribeDelegationToken",
      0, 2, 2 },
    { KAFKA_DELETE_GROUPS,                 "DeleteGroups",
      0, 2, 2 },
    { KAFKA_ELECT_LEADERS,                 "ElectLeaders",
      0, 2, 2 },
    { KAFKA_INC_ALTER_CONFIGS,             "IncrementalAlterConfigs",
      0, 1, 1 },
    { KAFKA_ALTER_PARTITION_REASSIGNMENTS, "AlterPartitionReassignments",
      0, 0, 0 },
    { KAFKA_LIST_PARTITION_REASSIGNMENTS,  "ListPartitionReassignments",
      0, 0, 0 },
    { KAFKA_OFFSET_DELETE,                 "OffsetDelete",
      0, 0, -1 },
    { KAFKA_DESCRIBE_CLUSTER,              "DescribeCluster",
      0, 1, 0 },
    { KAFKA_ALLOCATE_PRODUCER_IDS,         "AllocateProducerIds",
      0, 0, 0 },
};

/*
 * Generated from kafka_apis. Add 1 to length for last dummy element.
 */
static value_string kafka_api_names[array_length(kafka_apis) + 1];

/*
 * For the current list of error codes check here:
 * https://github.com/apache/kafka/blob/trunk/clients/src/main/java/org/apache/kafka/common/protocol/Errors.java
 */
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
    { 15, "The Coordinator is not Available" },
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
    { 43, "Unsupported for Message Format" },
    { 44, "Policy Violation" },
    { 45, "Out of Order Sequence Number" },
    { 46, "Duplicate Sequence Number" },
    { 47, "Invalid Producer Epoch" },
    { 48, "Invalid Transaction State" },
    { 49, "Invalid Producer ID Mapping" },
    { 50, "Invalid Transaction Timeout" },
    { 51, "Concurrent Transactions" },
    { 52, "Transaction Coordinator Fenced" },
    { 53, "Transactional ID Authorization Failed" },
    { 54, "Security Disabled" },
    { 55, "Operation not Attempted" },
    { 56, "Kafka Storage Error" },
    { 57, "Log Directory not Found" },
    { 58, "SASL Authentication failed" },
    { 59, "Unknown Producer ID" },
    { 60, "Partition Reassignment in Progress" },
    { 61, "Delegation Token Auth Disabled" },
    { 62, "Delegation Token not Found" },
    { 63, "Delegation Token Owner Mismatch" },
    { 64, "Delegation Token Request not Allowed" },
    { 65, "Delegation Token Authorization Failed" },
    { 66, "Delegation Token Expired" },
    { 67, "Supplied Principal Type Unsupported" },
    { 68, "Not Empty Group" },
    { 69, "Group ID not Found" },
    { 70, "Fetch Session ID not Found" },
    { 71, "Invalid Fetch Session Epoch" },
    { 72, "Listener not Found" },
    { 73, "Topic Deletion Disabled" },
    { 74, "Fenced Leader Epoch" },
    { 75, "Unknown Leader Epoch" },
    { 76, "Unsupported Compression Type" },
    { 77, "Stale Broker Epoch" },
    { 78, "Offset not Available" },
    { 79, "Member ID Required" },
    { 80, "Preferred Leader not Available" },
    { 81, "Group Max Size Reached" },
    { 82, "Fenced Instance ID" },
    { 83, "Eligible topic partition leaders are not available" },
    { 84, "Leader election not needed for topic partition" },
    { 85, "No partition reassignment is in progress" },
    { 86, "Deleting offsets of a topic is forbidden while the consumer group is actively subscribed to it" },
    { 87, "This record has failed the validation on broker and hence will be rejected" },
    { 88, "There are unstable offsets that need to be cleared" },
    { 89, "The throttling quota has been exceeded." },
    { 90, "There is a newer producer with the same transactionalId which fences the current one." },
    { 91, "A request illegally referred to a resource that does not exist." },
    { 92, "A request illegally referred to the same resource twice." },
    { 93, "Requested credential would not meet criteria for acceptability." },
    { 94, "Indicates that the either the sender or recipient of a voter-only request is not one of the expected voters." },
    { 95, "The given update version was invalid." },
    { 96, "Unable to update finalized features due to an unexpected server error." },
    { 97, "Request principal deserialization failed during forwarding. This indicates an internal error on the broker cluster security setup." },
    { 98, "Requested snapshot was not found." },
    { 99, "Requested position is not greater than or equal to zero, and less than the size of the snapshot." },
    { 100, "This server does not host this topic ID." },
    { 101, "This broker ID is already in use." },
    { 102, "The given broker ID was not registered." },
    { 103, "The log's topic ID did not match the topic ID in the request." },
    { 104, "The clusterId in the request does not match that found on the server." },
    { 105, "The transactionalId could not be found." },
    { 106, "The fetch session encountered inconsistent topic ID usage." },
    { 107, "The new ISR contains at least one ineligible replica." },
    { 108, "The AlterPartition request successfully updated the partition state but the leader has changed." },
    { 109, "The requested offset is moved to tiered storage." },
    { 110, "The member epoch is fenced by the group coordinator. The member must abandon all its partitions and rejoin." },
    { 111, "The instance ID is still used by another member in the consumer group. That member must leave first." },
    { 112, "The assignor or its version range is not supported by the consumer group." },
    { 113, "The member epoch is stale. The member must retry after receiving its updated member epoch via the ConsumerGroupHeartbeat API." },
    { 114, "The request was sent to an endpoint of the wrong type." },
    { 115, "This endpoint type is not supported yet." },
    { 116, "This controller ID is not known." },
    { 117, "Client sent a push telemetry request with an invalid or outdated subscription ID." },
    { 118, "Client sent a push telemetry request larger than the maximum size the broker will accept." },
    { 119, "The controller has considered the broker registration to be invalid." },
    { 120, "The server encountered an error with the transaction. The client can abort the transaction to continue using this transactional ID." },
    { 0, NULL }
};

#define KAFKA_ACK_NOT_REQUIRED 0
#define KAFKA_ACK_LEADER       1
#define KAFKA_ACK_FULL_ISR     -1
static const value_string kafka_acks[] = {
    { KAFKA_ACK_NOT_REQUIRED, "Not Required" },
    { KAFKA_ACK_LEADER,       "Leader"       },
    { KAFKA_ACK_FULL_ISR,     "Full ISR"     },
    { 0, NULL }
};

#define KAFKA_MESSAGE_CODEC_MASK   0x07
#define KAFKA_MESSAGE_CODEC_NONE   0
#define KAFKA_MESSAGE_CODEC_GZIP   1
#define KAFKA_MESSAGE_CODEC_SNAPPY 2
#define KAFKA_MESSAGE_CODEC_LZ4    3
#define KAFKA_MESSAGE_CODEC_ZSTD   4
static const value_string kafka_message_codecs[] = {
    { KAFKA_MESSAGE_CODEC_NONE,   "None"   },
    { KAFKA_MESSAGE_CODEC_GZIP,   "Gzip"   },
    { KAFKA_MESSAGE_CODEC_SNAPPY, "Snappy" },
    { KAFKA_MESSAGE_CODEC_LZ4,    "LZ4"    },
    { KAFKA_MESSAGE_CODEC_ZSTD,   "Zstd"   },
    { 0, NULL }
};
#ifdef HAVE_SNAPPY
static const uint8_t kafka_xerial_header[8] = {0x82, 0x53, 0x4e, 0x41, 0x50, 0x50, 0x59, 0x00};
#endif

#define KAFKA_MESSAGE_TIMESTAMP_MASK 0x08
static const value_string kafka_message_timestamp_types[] = {
    { 0, "CreateTime" },
    { 1, "LogAppendTime" },
    { 0, NULL }
};

#define KAFKA_BATCH_TRANSACTIONAL_MASK 0x10
static const value_string kafka_batch_transactional_values[] = {
    { 0, "Non-transactional" },
    { 1, "Transactional" },
    { 0, NULL }
};

#define KAFKA_BATCH_CONTROL_BATCH_MASK 0x20
static const value_string kafka_batch_control_batch_values[] = {
    { 0, "Data batch" },
    { 1, "Control batch" },
    { 0, NULL }
};

static const value_string kafka_coordinator_types[] = {
    { 0, "Group" },
    { 1, "Transaction" },
    { 0, NULL }
};

static const value_string kafka_security_protocol_types[] = {
    { 0, "PLAINTEXT" },
    { 1, "SSL" },
    { 2, "SASL_PLAINTEXT" },
    { 3, "SASL_SSL" },
    { 0, NULL }
};

static const value_string kafka_isolation_levels[] = {
    { 0, "Read Uncommitted" },
    { 1, "Read Committed" },
    { 0, NULL }
};

static const value_string kafka_transaction_results[] = {
    { 0, "ABORT" },
    { 1, "COMMIT" },
    { 0, NULL }
};

static const value_string acl_resource_types[] = {
    { 0, "Unknown" },
    { 1, "Any" },
    { 2, "Topic" },
    { 3, "Group" },
    { 4, "Cluster" },
    { 5, "TransactionalId" },
    { 6, "DelegationToken" },
    { 0, NULL }
};

static const value_string acl_resource_pattern_types[] = {
    { 0, "Unknown" },
    { 1, "Any" },
    { 2, "Match" },
    { 3, "Literal" },
    { 4, "Prefixed" },
    { 0, NULL }
};

static const value_string acl_operations[] = {
    { 0, "Unknown" },
    { 1, "Any" },
    { 2, "All" },
    { 3, "Read" },
    { 4, "Write" },
    { 5, "Create" },
    { 6, "Delete" },
    { 7, "Alter" },
    { 8, "Describe" },
    { 9, "Cluster Action" },
    { 10, "Describe Configs" },
    { 11, "Alter Configs" },
    { 12, "Idempotent Write" },
    { 0, NULL }
};

static const value_string acl_permission_types[] = {
    { 0, "Unknown" },
    { 1, "Any" },
    { 2, "Deny" },
    { 3, "Allow" },
    { 0, NULL }
};

static const value_string config_resource_types[] = {
    { 0, "Unknown" },
    { 2, "Topic" },
    { 4, "Broker" },
    { 0, NULL }
};

static const value_string config_sources[] = {
    { 0, "Unknown" },
    { 1, "Topic" },
    { 2, "Broker (Dynamic)" },
    { 3, "Broker (Dynamic/Default)" },
    { 4, "Broker (Static)" },
    { 5, "Default" },
    { 0, NULL }
};

static const value_string config_operations[] = {
    { 0, "Set" },
    { 1, "Delete" },
    { 2, "Append" },
    { 3, "Subtract" },
    { 0, NULL }
};

static const value_string election_types[] = {
    { 0, "Preferred" },
    { 1, "Unclean" },
    { 0, NULL }
};

/* Whether to show the lengths of string and byte fields in the protocol tree.
 * It can be useful to see these, but they do clutter up the display, so disable
 * by default */
static bool kafka_show_string_bytes_lengths;

typedef struct _kafka_query_response_t {
    kafka_api_key_t     api_key;
    kafka_api_version_t api_version;
    uint32_t correlation_id;
    uint32_t request_frame;
    uint32_t response_frame;
    bool response_found;
    bool flexible_api;
} kafka_query_response_t;


/* Some values to temporarily remember during dissection */
typedef struct kafka_packet_values_t {
    kafka_partition_t partition_id;
    kafka_offset_t    offset;
} kafka_packet_values_t;

/* Forward declaration (dissect_kafka_regular_message_set() and dissect_kafka_message() call each other...) */
static int
dissect_kafka_regular_message_set(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset, unsigned len, uint8_t codec);


/* HELPERS */

#ifdef HAVE_LZ4FRAME_H
/* Local copy of XXH32() algorithm as found in https://github.com/lz4/lz4/blob/v1.7.5/lib/xxhash.c
   as some packagers are not providing xxhash.h in liblz4 */
typedef struct {
    uint32_t total_len_32;
    uint32_t large_len;
    uint32_t v1;
    uint32_t v2;
    uint32_t v3;
    uint32_t v4;
    uint32_t mem32[4];   /* buffer defined as U32 for alignment */
    uint32_t memsize;
    uint32_t reserved;   /* never read nor write, will be removed in a future version */
} XXH32_state_t;

typedef enum {
    XXH_bigEndian=0,
    XXH_littleEndian=1
} XXH_endianess;

static const int g_one = 1;
#define XXH_CPU_LITTLE_ENDIAN   (*(const char*)(&g_one))

static const uint32_t PRIME32_1 = 2654435761U;
static const uint32_t PRIME32_2 = 2246822519U;
static const uint32_t PRIME32_3 = 3266489917U;
static const uint32_t PRIME32_4 =  668265263U;
static const uint32_t PRIME32_5 =  374761393U;

#define XXH_rotl32(x,r) ((x << r) | (x >> (32 - r)))

static uint32_t XXH_read32(const void* memPtr)
{
    uint32_t val;
    memcpy(&val, memPtr, sizeof(val));
    return val;
}

static uint32_t XXH_swap32(uint32_t x)
{
    return  ((x << 24) & 0xff000000 ) |
            ((x <<  8) & 0x00ff0000 ) |
            ((x >>  8) & 0x0000ff00 ) |
            ((x >> 24) & 0x000000ff );
}

#define XXH_readLE32(ptr, endian) (endian==XXH_littleEndian ? XXH_read32(ptr) : XXH_swap32(XXH_read32(ptr)))

static uint32_t XXH32_round(uint32_t seed, uint32_t input)
{
    seed += input * PRIME32_2;
    seed  = XXH_rotl32(seed, 13);
    seed *= PRIME32_1;
    return seed;
}

static uint32_t XXH32_endian(const void* input, size_t len, uint32_t seed, XXH_endianess endian)
{
    const int8_t* p = (const int8_t*)input;
    const int8_t* bEnd = p + len;
    uint32_t h32;
#define XXH_get32bits(p) XXH_readLE32(p, endian)

    if (len>=16) {
        const int8_t* const limit = bEnd - 16;
        uint32_t v1 = seed + PRIME32_1 + PRIME32_2;
        uint32_t v2 = seed + PRIME32_2;
        uint32_t v3 = seed + 0;
        uint32_t v4 = seed - PRIME32_1;

        do {
            v1 = XXH32_round(v1, XXH_get32bits(p)); p+=4;
            v2 = XXH32_round(v2, XXH_get32bits(p)); p+=4;
            v3 = XXH32_round(v3, XXH_get32bits(p)); p+=4;
            v4 = XXH32_round(v4, XXH_get32bits(p)); p+=4;
        } while (p<=limit);

        h32 = XXH_rotl32(v1, 1) + XXH_rotl32(v2, 7) + XXH_rotl32(v3, 12) + XXH_rotl32(v4, 18);
    } else {
        h32  = seed + PRIME32_5;
    }

    h32 += (uint32_t) len;

    while (p+4<=bEnd) {
        h32 += XXH_get32bits(p) * PRIME32_3;
        h32  = XXH_rotl32(h32, 17) * PRIME32_4 ;
        p+=4;
    }

    while (p<bEnd) {
        h32 += (*p) * PRIME32_5;
        h32 = XXH_rotl32(h32, 11) * PRIME32_1 ;
        p++;
    }

    h32 ^= h32 >> 15;
    h32 *= PRIME32_2;
    h32 ^= h32 >> 13;
    h32 *= PRIME32_3;
    h32 ^= h32 >> 16;

    return h32;
}

static unsigned XXH32(const void* input, size_t len, unsigned seed)
{
    XXH_endianess endian_detected = (XXH_endianess)XXH_CPU_LITTLE_ENDIAN;
    if (endian_detected==XXH_littleEndian)
        return XXH32_endian(input, len, seed, XXH_littleEndian);
    else
        return XXH32_endian(input, len, seed, XXH_bigEndian);
}
#endif /* HAVE_LZ4FRAME_H */

static const char *
kafka_error_to_str(kafka_error_t error)
{
    return val_to_str(error, kafka_errors, "Unknown %d");
}

static const char *
kafka_api_key_to_str(kafka_api_key_t api_key)
{
    return val_to_str(api_key, kafka_api_names, "Unknown %d");
}

static const kafka_api_info_t *
kafka_get_api_info(kafka_api_key_t api_key)
{
    // short-circuit on obvious garbage - Kafka API keys are always positive
    if (api_key < 0) {
        return NULL;
    }

    // Kafka API keys are a sparse array (non-contiguous) so we have to walk the known API keys to see if this is
    // one of them
    for (uint32_t i = 0; i < array_length(kafka_apis); i++) {
        if (kafka_apis[i].api_key == api_key) {
            return &kafka_apis[i];
        }
    }

    return NULL;
}

/*
 * Check if the API version uses flexible coding. Flexible coding was introduced in Kafka 2.4.
 * The major changes in the flexible versions:
 * - string length is stored as varint instead of int16
 * - the header and message content may include additional flexible fields.
 * The flexible version affects also the header. Normally the header version is 1.
 * Flexible API headers are version 2. There are two hardcoded exceptions. ControlledShutdown
 * request always uses header version 0. Same applies for ApiVersions response. These cases
 * have to be covered in the message parsing.
 */
static bool
kafka_is_api_version_flexible(kafka_api_key_t api_key, kafka_api_version_t api_version)
{
    const kafka_api_info_t *api_info;
    api_info = kafka_get_api_info(api_key);
    return api_info != NULL && !(api_info->flexible_since == -1 || api_version < api_info->flexible_since);
}

static bool
kafka_is_api_version_supported(const kafka_api_info_t *api_info, kafka_api_version_t api_version)
{
    DISSECTOR_ASSERT(api_info);

    return !(api_info->min_version == -1 ||
             api_version < api_info->min_version ||
             api_version > api_info->max_version);
}

static void
kafka_check_supported_api_key(packet_info *pinfo, proto_item *ti, kafka_query_response_t *matcher)
{
    if (kafka_get_api_info(matcher->api_key) == NULL) {
        col_append_str(pinfo->cinfo, COL_INFO, " [Unknown API key]");
        expert_add_info_format(pinfo, ti, &ei_kafka_unknown_api_key,
                               "%s API key", kafka_api_key_to_str(matcher->api_key));
    }
}

static kafka_api_version_t
kafka_check_supported_api_version(packet_info *pinfo, proto_item *ti, kafka_query_response_t *matcher)
{
    const kafka_api_info_t *api_info;
    kafka_api_version_t dissect_version = matcher->api_version;

    api_info = kafka_get_api_info(matcher->api_key);
    if (api_info != NULL && !kafka_is_api_version_supported(api_info, matcher->api_version)) {
        col_append_str(pinfo->cinfo, COL_INFO, " [Unsupported API version]");
        if (api_info->min_version == -1) {
            expert_add_info_format(pinfo, ti, &ei_kafka_unsupported_api_version,
                                   "Unsupported %s version.",
                                   kafka_api_key_to_str(matcher->api_key));
            dissect_version = api_info->min_version;
        }
        else if (api_info->min_version == api_info->max_version) {
            expert_add_info_format(pinfo, ti, &ei_kafka_unsupported_api_version,
                                   "Unsupported %s version. Supports v%d.",
                                   kafka_api_key_to_str(matcher->api_key), api_info->min_version);
            dissect_version = api_info->min_version;
            expert_add_info_format(pinfo, ti, &ei_kafka_assumed_api_version,
                                   "Dissecting assuming v%d.",
                                   dissect_version);
        } else {
            expert_add_info_format(pinfo, ti, &ei_kafka_unsupported_api_version,
                                   "Unsupported %s version. Supports v%d-%d.",
                                   kafka_api_key_to_str(matcher->api_key),
                                   api_info->min_version, api_info->max_version);
            if (matcher->api_version < 0 || matcher->api_version > api_info->max_version) {
                dissect_version = api_info->max_version;
            } else {
                dissect_version = api_info->min_version;
            }
            expert_add_info_format(pinfo, ti, &ei_kafka_assumed_api_version,
                                   "Dissecting assuming v%d.",
                                   dissect_version);
        }
    }

    return dissect_version;
}

static int
dissect_kafka_array_elements(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, int offset,
                        kafka_api_version_t api_version,
                        int(*func)(tvbuff_t*, packet_info*, proto_tree*, int, kafka_api_version_t),
                        int count)
{
    int i;
    int next_offset;

    // sanity check - we expect at least 1 byte per array item
    if (tvb_reported_length_remaining(tvb, offset) < count) {
        expert_add_info(pinfo, proto_tree_get_parent(tree), &ei_kafka_bad_array_length);
        return offset;
    }

    for (i=0; i<count; i++) {
        next_offset = func(tvb, pinfo, tree, offset, api_version);

        // sanity check - the offset should advance for each field we read
        if (next_offset == offset) {
            expert_add_info(pinfo, proto_tree_get_parent(tree), &ei_kafka_zero_field_length);
            break;
        }

        offset = next_offset;
    }
    return offset;
}

/*
 * In the pre KIP-482 the arrays had length saved in 32-bit signed integer. If the value was -1,
 * the array was considered to be null.
 */
static int
dissect_kafka_regular_array(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, int offset,
                    kafka_api_version_t api_version,
                    int(*func)(tvbuff_t*, packet_info*, proto_tree*, int, kafka_api_version_t),
                    int *p_count)
{
    int32_t count;

    count = (int32_t) tvb_get_ntohl(tvb, offset);
    offset += 4;

    if (count < -1) { // -1 means null array
        expert_add_info(pinfo, proto_tree_get_parent(tree), &ei_kafka_bad_array_length);
        return offset;
    }

    offset = dissect_kafka_array_elements(tree, tvb, pinfo, offset, api_version, func, count);

    if (p_count != NULL) *p_count = count;

    return offset;
}

/*
 * KIP-482 introduced concept of compact arrays. If API version for the given call is marked flexible,
 * all arrays are prefixed with unsigned varint. The value is the array length + 1. If the value is 0,
 * the array is null.
 */
static int
dissect_kafka_compact_array(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, int offset,
                        kafka_api_version_t api_version,
                        int(*func)(tvbuff_t*, packet_info*, proto_tree*, int, kafka_api_version_t),
                        int *p_count)
{
    int64_t count;
    int32_t len;

    len = tvb_get_varint(tvb, offset, FT_VARINT_MAX_LEN, &count, ENC_VARINT_PROTOBUF);
    if (len == 0) {
        expert_add_info(pinfo, proto_tree_get_parent(tree), &ei_kafka_bad_varint);
        return tvb_captured_length(tvb);
    }
    if(count > 0x7ffffffL) {
        expert_add_info(pinfo, proto_tree_get_parent(tree), &ei_kafka_bad_array_length);
        return offset + len;
    }
    offset += len;

    /*
     * Compact arrays store count+1
     * https://cwiki.apache.org/confluence/display/KAFKA/KIP-482%3A+The+Kafka+Protocol+should+Support+Optional+Tagged+Fields
     */
    offset = dissect_kafka_array_elements(tree, tvb, pinfo, offset, api_version, func, (int)count - 1);

    if (p_count != NULL) *p_count = (int)count - 1;

    return offset;
}

/*
 * Dissect array. Use 'flexible' flag to select which variant should be used.
 */
static int
dissect_kafka_array(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, int offset, int flexible,
                            kafka_api_version_t api_version,
                            int(*func)(tvbuff_t*, packet_info*, proto_tree*, int, kafka_api_version_t),
                            int *p_count)
{
    if (flexible) {
        return dissect_kafka_compact_array(tree, tvb, pinfo, offset, api_version, func, p_count);
    } else {
        return dissect_kafka_regular_array(tree, tvb, pinfo, offset, api_version, func, p_count);
    }

}

/* kept for completeness */
static int
dissect_kafka_varint(proto_tree *tree, int hf_item, tvbuff_t *tvb, packet_info *pinfo, int offset,
                     int64_t *p_value) _U_;
static int
dissect_kafka_varint(proto_tree *tree, int hf_item, tvbuff_t *tvb, packet_info *pinfo, int offset,
                     int64_t *p_value)
{
    int64_t value;
    unsigned len;
    proto_item *pi;

    len = tvb_get_varint(tvb, offset, FT_VARINT_MAX_LEN, &value, ENC_VARINT_ZIGZAG);
    pi = proto_tree_add_int64(tree, hf_item, tvb, offset, len, value);

    if (len == 0) {
        expert_add_info(pinfo, pi, &ei_kafka_bad_varint);
        return tvb_captured_length(tvb);
    }

    if (p_value != NULL) *p_value = value;

    return offset + len;
}

static int
dissect_kafka_varuint(proto_tree *tree, int hf_item, tvbuff_t *tvb, packet_info *pinfo, int offset,
                      uint64_t *p_value)
{
    uint64_t value;
    unsigned len;
    proto_item *pi;

    len = tvb_get_varint(tvb, offset, FT_VARINT_MAX_LEN, &value, ENC_VARINT_PROTOBUF);
    pi = proto_tree_add_uint64(tree, hf_item, tvb, offset, len, value);

    if (len == 0) {
        expert_add_info(pinfo, pi, &ei_kafka_bad_varint);
        return tvb_captured_length(tvb);
    }

    if (p_value != NULL) *p_value = value;

    return offset + len;
}


/*
 * Retrieve null-terminated copy of string from a package.
 * The function wraps the tvb_get_string_enc that if given string is NULL, which is represented as negative length,
 * a substitute string is returned instead of failing.
 */
static int8_t*
kafka_tvb_get_string(wmem_allocator_t *pool, tvbuff_t *tvb, int offset, int length)
{
    if (length>=0) {
        return tvb_get_string_enc(pool, tvb, offset, length, ENC_UTF_8);
    } else {
        return "[ Null ]";
    }
}

/*
 * Pre KIP-482 coding. The string is prefixed with 16-bit signed integer. Value -1 means null.
 */
static int
dissect_kafka_regular_string(proto_tree *tree, int hf_item, tvbuff_t *tvb, packet_info *pinfo, int offset,
                     int *p_offset, int *p_length)
{
    int16_t length;
    proto_item *pi;

    length = (int16_t) tvb_get_ntohs(tvb, offset);
    if (length < -1) {
        pi = proto_tree_add_item(tree, hf_item, tvb, offset, 0, ENC_NA);
        expert_add_info(pinfo, pi, &ei_kafka_bad_string_length);
        if (p_offset) {
            *p_offset = 2;
        }
        if (p_length) {
            *p_length = 0;
        }
        return offset + 2;
    }

    if (length == -1) {
        proto_tree_add_string(tree, hf_item, tvb, offset, 2, NULL);
    } else {
        proto_tree_add_string(tree, hf_item, tvb, offset, length + 2,
                              kafka_tvb_get_string(pinfo->pool, tvb, offset + 2, length));
    }

    if (p_offset != NULL) *p_offset = offset + 2;
    if (p_length != NULL) *p_length = length;

    offset += 2;
    if (length != -1) offset += length;

    return offset;
}

/*
 * Compact coding. The string is prefixed with unsigned varint containing number of octets + 1.
 */
static int
dissect_kafka_compact_string(proto_tree *tree, int hf_item, tvbuff_t *tvb, packet_info *pinfo, int offset,
                             int *p_offset, int *p_length)
{
    unsigned len;
    uint64_t length;
    proto_item *pi;

    len = tvb_get_varint(tvb, offset, FT_VARINT_MAX_LEN, &length, ENC_VARINT_PROTOBUF);

    if (len == 0) {
        pi = proto_tree_add_item(tree, hf_item, tvb, offset, 0, ENC_NA);
        expert_add_info(pinfo, pi, &ei_kafka_bad_varint);
        if (p_offset) {
            *p_offset = 0;
        }
        if (p_length) {
            *p_length = 0;
        }
        return tvb_captured_length(tvb);
    }

    if (length == 0) {
        proto_tree_add_string(tree, hf_item, tvb, offset, len, NULL);
    } else {
        proto_tree_add_string(tree, hf_item, tvb, offset, len + (int)length - 1,
                              kafka_tvb_get_string(pinfo->pool, tvb, offset + len, (int)length - 1));
    }

    if (p_offset != NULL) *p_offset = offset + len;
    if (p_length != NULL) *p_length = (int)length - 1;

    offset += len;
    if (length > 0) {
        offset += (int)length - 1;
    }

    return offset;
}

/*
 * Dissect string. Depending on the 'flexible' flag use old style or compact coding.
 */
static int
dissect_kafka_string(proto_tree *tree, int hf_item, tvbuff_t *tvb, packet_info *pinfo, int offset, int flexible,
                             int *p_offset, int *p_length)
{
    if (flexible) {
        return dissect_kafka_compact_string(tree, hf_item, tvb, pinfo, offset, p_offset, p_length);
    } else {
        return dissect_kafka_regular_string(tree, hf_item, tvb, pinfo, offset, p_offset, p_length);
    }
}

/*
 * Pre KIP-482 coding. The string is prefixed with signed 32-bit integer containing number of octets.
 */
static int
dissect_kafka_regular_bytes(proto_tree *tree, int hf_item, tvbuff_t *tvb, packet_info *pinfo, int offset,
                    int *p_offset, int *p_length)
{
    int32_t length;
    proto_item *pi;

    length = (int32_t) tvb_get_ntohl(tvb, offset);
    if (length < -1) {
        pi = proto_tree_add_item(tree, hf_item, tvb, offset, 0, ENC_NA);
        expert_add_info(pinfo, pi, &ei_kafka_bad_string_length);
        if (p_offset) {
            *p_offset = 4;
        }
        if (p_length) {
            *p_length = 0;
        }
        return offset + 4;
    }

    if (length == -1) {
        proto_tree_add_bytes_with_length(tree, hf_item, tvb, offset, 4, NULL, 0);
    } else {
        proto_tree_add_bytes_with_length(tree, hf_item, tvb, offset, length + 4,
                                         tvb_get_ptr(tvb, offset + 4, length), length);
    }

    if (p_offset != NULL) *p_offset = offset + 4;
    if (p_length != NULL) *p_length = length;

    offset += 4;
    if (length != -1) offset += length;

    return offset;
}

/*
 * Compact coding. The bytes are prefixed with unsigned varint containing number of octets + 1.
 */
static int
dissect_kafka_compact_bytes(proto_tree *tree, int hf_item, tvbuff_t *tvb, packet_info *pinfo, int offset,
                    int *p_offset, int *p_length)
{
    unsigned len;
    uint64_t length;
    proto_item *pi;

    len = tvb_get_varint(tvb, offset, FT_VARINT_MAX_LEN, &length, ENC_VARINT_PROTOBUF);

    if (len == 0) {
        pi = proto_tree_add_item(tree, hf_item, tvb, offset, 0, ENC_NA);
        expert_add_info(pinfo, pi, &ei_kafka_bad_varint);
        if (p_offset) {
            *p_offset = 0;
        }
        if (p_length) {
            *p_length = 0;
        }
        return tvb_captured_length(tvb);
    }

    if (length == 0) {
        proto_tree_add_bytes_with_length(tree, hf_item, tvb, offset, len, NULL, 0);
    } else {
        proto_tree_add_bytes_with_length(tree, hf_item, tvb, offset, len + (int)length - 1,
                                         tvb_get_ptr(tvb, offset + len, (int)length - 1),
                                         (int)length - 1);
    }

    if (p_offset != NULL) *p_offset = offset + len;
    if (p_length != NULL) *p_length = (int)length - 1;

    if (length == 0) {
        offset += len;
    } else {
        offset += len + (int)length - 1;
    }

    return offset;
}

/*
 * Dissect byte buffer. Depending on the 'flexible' flag use old style or compact coding.
 */
static int
dissect_kafka_bytes(proto_tree *tree, int hf_item, tvbuff_t *tvb, packet_info *pinfo, int offset, int flexible,
                     int *p_offset, int *p_length)
{
    if (flexible) {
        return dissect_kafka_compact_bytes(tree, hf_item, tvb, pinfo, offset, p_offset, p_length);
    } else {
        return dissect_kafka_regular_bytes(tree, hf_item, tvb, pinfo, offset, p_offset, p_length);
    }
}

static int
dissect_kafka_timestamp_delta(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, int hf_item, int offset, uint64_t first_timestamp)
{
    nstime_t   nstime;
    uint64_t   milliseconds;
    uint64_t   val;
    unsigned   len;
    proto_item *pi;

    len = tvb_get_varint(tvb, offset, FT_VARINT_MAX_LEN, &val, ENC_VARINT_ZIGZAG);

    milliseconds = first_timestamp + val;
    nstime.secs  = (time_t) (milliseconds / 1000);
    nstime.nsecs = (int) ((milliseconds % 1000) * 1000000);

    pi = proto_tree_add_time(tree, hf_item, tvb, offset, len, &nstime);
    if (len == 0) {
        expert_add_info(pinfo, pi, &ei_kafka_bad_varint);
        return tvb_captured_length(tvb);
    }

    return offset+len;
}

static int
dissect_kafka_offset_delta(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, int hf_item, int offset, uint64_t base_offset)
{
    int64_t    val;
    unsigned   len;
    proto_item *pi;

    len = tvb_get_varint(tvb, offset, FT_VARINT_MAX_LEN, &val, ENC_VARINT_ZIGZAG);

    pi = proto_tree_add_int64(tree, hf_item, tvb, offset, len, base_offset+val);
    if (len == 0) {
        expert_add_info(pinfo, pi, &ei_kafka_bad_varint);
        return tvb_captured_length(tvb);
    }

    return offset+len;
}

static int
dissect_kafka_int8(proto_tree *tree, int hf_item, tvbuff_t *tvb, packet_info *pinfo _U_, int offset, int8_t *p_value)
{
    if (p_value != NULL) *p_value = tvb_get_int8(tvb, offset);
    proto_tree_add_item(tree, hf_item, tvb, offset, 1, ENC_NA);
    return offset+1;
}

static int
dissect_kafka_int16(proto_tree *tree, int hf_item, tvbuff_t *tvb, packet_info *pinfo _U_, int offset, int16_t *p_value)
{
    if (p_value != NULL) *p_value = tvb_get_int16(tvb, offset, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_item, tvb, offset, 2, ENC_BIG_ENDIAN);
    return offset+2;
}

static int
dissect_kafka_int32(proto_tree *tree, int hf_item, tvbuff_t *tvb, packet_info *pinfo _U_, int offset, int32_t *p_value)
{
    if (p_value != NULL) *p_value = tvb_get_int32(tvb, offset, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_item, tvb, offset, 4, ENC_BIG_ENDIAN);
    return offset+4;
}

static int
dissect_kafka_int64(proto_tree *tree, int hf_item, tvbuff_t *tvb, packet_info *pinfo _U_, int offset, int64_t *p_value)
{
    if (p_value != NULL) *p_value = tvb_get_int64(tvb, offset, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_item, tvb, offset, 8, ENC_BIG_ENDIAN);
    return offset+8;
}

static int
dissect_kafka_timestamp(proto_tree *tree, int hf_item, tvbuff_t *tvb, packet_info *pinfo _U_, int offset, int64_t *p_value)
{
    if (p_value != NULL) *p_value = tvb_get_int64(tvb, offset, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_item, tvb, offset, 8, ENC_TIME_MSECS | ENC_BIG_ENDIAN);
    return offset+8;
}

static int
dissect_kafka_uuid(proto_tree *tree, int hf_item, tvbuff_t *tvb, packet_info *pinfo _U_, int offset)
{
    proto_tree_add_item(tree, hf_item, tvb, offset, 16, ENC_BIG_ENDIAN);
    return offset + 16;
}

static int
dissect_kafka_bool(proto_tree *tree, int hf_item, tvbuff_t *tvb, packet_info *pinfo _U_, int offset)
{
    proto_tree_add_item(tree, hf_item, tvb, offset, 1, ENC_BIG_ENDIAN);
    return offset + 1;
}

/*
 * Function: dissect_kafka_string_new
 * ---------------------------------------------------
 * Decodes UTF-8 string using the new length encoding. This format is used
 * in the v2 message encoding, where the string length is encoded using
 * ProtoBuf's ZigZag integer format (inspired by Avro). The main advantage
 * of ZigZag is very compact representation for small numbers.
 *
 * tvb: actual data buffer
 * pinfo: packet information
 * tree: protocol information tree to append the item
 * hf_item: protocol information item descriptor index
 * offset: offset in the buffer where the string length is to be found
 * p_display_string: pointer to a variable to store a pointer to the string value
 *
 * returns: offset of the next field in the message. If supplied, p_display_string
 * is guaranteed to be set to a valid value.
 */
static int
dissect_kafka_string_new(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int hf_item, int offset, char **p_display_string)
{
    int64_t val;
    unsigned len;
    proto_item *pi;

    if (p_display_string != NULL)
        *p_display_string = "<INVALID>";
    len = tvb_get_varint(tvb, offset, 5, &val, ENC_VARINT_ZIGZAG);

    if (len == 0) {
        pi = proto_tree_add_string_format_value(tree, hf_item, tvb, offset+len, 0, NULL, "<INVALID>");
        expert_add_info(pinfo, pi, &ei_kafka_bad_varint);
        return tvb_captured_length(tvb);
    } else if (val > 0) {
        // there is payload available, possibly with 0 octets
        if (p_display_string != NULL)
            proto_tree_add_item_ret_display_string(tree, hf_item, tvb, offset+len, (int)val, ENC_UTF_8, pinfo->pool, p_display_string);
        else
            proto_tree_add_item(tree, hf_item, tvb, offset+len, (int)val, ENC_UTF_8);
    } else if (val == 0) {
        // there is empty payload (0 octets)
        proto_tree_add_string_format_value(tree, hf_item, tvb, offset+len, 0, NULL, "<EMPTY>");
        if (p_display_string != NULL)
            *p_display_string = "<EMPTY>";
    } else if (val == -1) {
        // there is no payload (null)
        proto_tree_add_string_format_value(tree, hf_item, tvb, offset+len, 0, NULL, "<NULL>");
        val = 0;
    } else {
        pi = proto_tree_add_string_format_value(tree, hf_item, tvb, offset+len, 0, NULL, "<INVALID>");
        expert_add_info(pinfo, pi, &ei_kafka_bad_string_length);
        val = 0;
    }

    return offset+len+(int)val;
}

/*
 * Function: dissect_kafka_bytes_new
 * ---------------------------------------------------
 * Decodes byte buffer using the new length encoding. This format is used
 * in the v2 message encoding, where the buffer length is encoded using
 * ProtoBuf's ZigZag integer format (inspired by Avro). The main advantage
 * of ZigZag is very compact representation for small numbers.
 *
 * tvb: actual data buffer
 * pinfo: packet information (unused)
 * tree: protocol information tree to append the item
 * hf_item: protocol information item descriptor index
 * offset: offset in the buffer where the string length is to be found
 * p_bytes_offset: pointer to a variable to store the actual buffer begin
 * p_bytes_length: pointer to a variable to store the actual buffer length
 * p_invalid: pointer to a variable to store whether the length is valid
 *
 * returns: pointer to the next field in the message
 */
static int
dissect_kafka_bytes_new(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, int hf_item, int offset, int *p_bytes_offset, int *p_bytes_length, bool *p_invalid)
{
    int64_t    val;
    unsigned   len;
    proto_item *pi;

    *p_invalid = false;

    len = tvb_get_varint(tvb, offset, 5, &val, ENC_VARINT_ZIGZAG);

    if (len == 0) {
        pi = proto_tree_add_bytes_format_value(tree, hf_item, tvb, offset+len, 0, NULL, "<INVALID>");
        expert_add_info(pinfo, pi, &ei_kafka_bad_varint);
        return tvb_captured_length(tvb);
    } else if (val > 0) {
        // there is payload available, possibly with 0 octets
        proto_tree_add_item(tree, hf_item, tvb, offset+len, (int)val, ENC_NA);
    } else if (val == 0) {
        // there is empty payload (0 octets)
        proto_tree_add_bytes_format_value(tree, hf_item, tvb, offset+len, 0, NULL, "<EMPTY>");
    } else if (val == -1) {
        // there is no payload (null)
        proto_tree_add_bytes_format_value(tree, hf_item, tvb, offset+len, 0, NULL, "<NULL>");
        val = 0;
    } else {
        pi = proto_tree_add_bytes_format_value(tree, hf_item, tvb, offset+len, 0, NULL, "<INVALID>");
        expert_add_info(pinfo, pi, &ei_kafka_bad_bytes_length);
        val = 0;
        *p_invalid = true;
    }

    if (p_bytes_offset != NULL) {
        *p_bytes_offset = offset+len;
    }
    if (p_bytes_length != NULL) {
        *p_bytes_length = (int)val;
    }
    return offset+len+(int)val;
}

/* Calculate and show the reduction in transmitted size due to compression */
static void
show_compression_reduction(tvbuff_t *tvb, proto_tree *tree, unsigned compressed_size, unsigned uncompressed_size)
{
    proto_item *ti;
    /* Not really expecting a message to compress down to nothing, but defend against dividing by 0 anyway */
    if (uncompressed_size != 0) {
        ti = proto_tree_add_float(tree, hf_kafka_message_compression_reduction, tvb, 0, 0,
                                  (float)compressed_size / (float)uncompressed_size);
        proto_item_set_generated(ti);
    }
}

static int
dissect_kafka_record_headers_header(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset, bool *p_invalid)
{
    proto_item *header_ti;
    proto_tree *subtree;
    char *key_display_string;

    subtree = proto_tree_add_subtree(tree, tvb, offset, -1, ett_kafka_record_headers_header, &header_ti, "Header");

    offset = dissect_kafka_string_new(tvb, pinfo, subtree, hf_kafka_record_header_key, offset, &key_display_string);
    offset = dissect_kafka_bytes_new(tvb, pinfo, subtree, hf_kafka_record_header_value, offset, NULL, NULL, p_invalid);

    proto_item_append_text(header_ti, " (Key: %s)", key_display_string);

    proto_item_set_end(header_ti, tvb, offset);

    return offset;
}

static int
dissect_kafka_record_headers(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, int offset)
{
    proto_item *record_headers_ti;
    proto_tree *subtree;
    int64_t    count;
    unsigned   len;
    int        i;
    bool       invalid = false;

    subtree = proto_tree_add_subtree(tree, tvb, offset, -1, ett_kafka_record_headers, &record_headers_ti, "Headers");

    len = tvb_get_varint(tvb, offset, 5, &count, ENC_VARINT_ZIGZAG);
    if (len == 0) {
        expert_add_info(pinfo, record_headers_ti, &ei_kafka_bad_varint);
        return tvb_captured_length(tvb);
    } else if (count < -1) { // -1 means null array
        expert_add_info(pinfo, record_headers_ti, &ei_kafka_bad_array_length);
    }

    offset += len;
    for (i = 0; i < count && !invalid; i++) {
        offset = dissect_kafka_record_headers_header(tvb, pinfo, subtree, offset, &invalid);
    }

    proto_item_set_end(record_headers_ti, tvb, offset);

    return offset;
}

static int
dissect_kafka_record(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, int start_offset, uint64_t base_offset, uint64_t first_timestamp)
{
    proto_item *record_ti;
    proto_tree *subtree;

    int64_t    size;
    unsigned   len;

    int offset, end_offset;
    bool       invalid;

    offset = start_offset;

    subtree = proto_tree_add_subtree(tree, tvb, offset, -1, ett_kafka_record, &record_ti, "Record");

    len = tvb_get_varint(tvb, offset, 5, &size, ENC_VARINT_ZIGZAG);
    if (len == 0) {
        expert_add_info(pinfo, record_ti, &ei_kafka_bad_varint);
        return tvb_captured_length(tvb);
    } else if (size < 6) {
        expert_add_info(pinfo, record_ti, &ei_kafka_bad_record_length);
        return offset + len;
    }

    end_offset = offset + len + (int)size;
    offset += len;

    proto_tree_add_item(subtree, hf_kafka_record_attributes, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;

    offset = dissect_kafka_timestamp_delta(tvb, pinfo, subtree, hf_kafka_message_timestamp, offset, first_timestamp);
    offset = dissect_kafka_offset_delta(tvb, pinfo, subtree, hf_kafka_offset, offset, base_offset);

    offset = dissect_kafka_bytes_new(tvb, pinfo, subtree, hf_kafka_message_key, offset, NULL, NULL, &invalid);
    if (invalid)
        return end_offset;
    offset = dissect_kafka_bytes_new(tvb, pinfo, subtree, hf_kafka_message_value, offset, NULL, NULL, &invalid);
    if (invalid)
        return end_offset;

    offset = dissect_kafka_record_headers(tvb, pinfo, subtree, offset);

    if (offset != end_offset) {
        expert_add_info(pinfo, record_ti, &ei_kafka_bad_record_length);
    }

    proto_item_set_end(record_ti, tvb, end_offset);

    return end_offset;
}

static bool
decompress_none(tvbuff_t *tvb, packet_info *pinfo _U_, int offset, uint32_t length _U_, tvbuff_t **decompressed_tvb, int *decompressed_offset)
{
    *decompressed_tvb = tvb;
    *decompressed_offset = offset;
    return true;
}

static bool
decompress_gzip(tvbuff_t *tvb, packet_info *pinfo, int offset, uint32_t length, tvbuff_t **decompressed_tvb, int *decompressed_offset)
{
    *decompressed_tvb = tvb_child_uncompress_zlib(tvb, tvb, offset, length);
    *decompressed_offset = 0;
    if (*decompressed_tvb) {
        return true;
    } else {
        col_append_str(pinfo->cinfo, COL_INFO, " [gzip decompression failed] ");
        return false;
    }
}

#define MAX_LOOP_ITERATIONS 100

#ifdef HAVE_LZ4FRAME_H
static bool
decompress_lz4(tvbuff_t *tvb, packet_info *pinfo, int offset, uint32_t length, tvbuff_t **decompressed_tvb, int *decompressed_offset)
{
    LZ4F_decompressionContext_t lz4_ctxt = NULL;
    LZ4F_frameInfo_t lz4_info;
    LZ4F_errorCode_t rc = 0;
    size_t src_offset = 0, src_size = 0, dst_size = 0;
    unsigned char *decompressed_buffer = NULL;
    tvbuff_t *composite_tvb = NULL;

    bool ret = false;

    /* Prepare compressed data buffer */
    uint8_t *data = (uint8_t*)tvb_memdup(pinfo->pool, tvb, offset, length);
    /* Override header checksum to workaround buggy Kafka implementations */
    if (length > 7) {
        uint32_t hdr_end = 6;
        if (data[4] & 0x08) {
            hdr_end += 8;
        }
        if (hdr_end < length) {
            data[hdr_end] = (XXH32(&data[4], hdr_end - 4, 0) >> 8) & 0xff;
        }
    }

    /* Allocate output buffer */
    rc = LZ4F_createDecompressionContext(&lz4_ctxt, LZ4F_VERSION);
    if (LZ4F_isError(rc)) {
        goto end;
    }

    src_offset = length;
    rc = LZ4F_getFrameInfo(lz4_ctxt, &lz4_info, data, &src_offset);
    if (LZ4F_isError(rc)) {
        goto end;
    }

    switch (lz4_info.blockSizeID) {
        case LZ4F_max64KB:
            dst_size = 1 << 16;
            break;
        case LZ4F_max256KB:
            dst_size = 1 << 18;
            break;
        case LZ4F_max1MB:
            dst_size = 1 << 20;
            break;
        case LZ4F_max4MB:
            dst_size = 1 << 22;
            break;
        default:
            goto end;
    }

    if (lz4_info.contentSize && lz4_info.contentSize < dst_size) {
        dst_size = (size_t)lz4_info.contentSize;
    }

    size_t out_size;
    int count = 0;

    do {
        src_size = length - src_offset; // set the number of available octets
        if (src_size == 0) {
            goto end;
        }

        decompressed_buffer = wmem_alloc(pinfo->pool, dst_size);
        out_size = dst_size;
        rc = LZ4F_decompress(lz4_ctxt, decompressed_buffer, &out_size,
                              &data[src_offset], &src_size, NULL);
        if (LZ4F_isError(rc)) {
            goto end;
        }
        if (out_size != dst_size) {
            decompressed_buffer = (uint8_t *)wmem_realloc(pinfo->pool, decompressed_buffer, out_size);
        }
        if (out_size == 0) {
            goto end;
        }
        if (!composite_tvb) {
            composite_tvb = tvb_new_composite();
        }
        tvb_composite_append(composite_tvb,
                             tvb_new_child_real_data(tvb, (uint8_t*)decompressed_buffer, (unsigned)out_size, (int)out_size));
        src_offset += src_size; // bump up the offset for the next iteration
        DISSECTOR_ASSERT_HINT(count < MAX_LOOP_ITERATIONS, "MAX_LOOP_ITERATIONS exceeded");
    } while (rc > 0 && count++ < MAX_LOOP_ITERATIONS);

    ret = true;
end:
    if (composite_tvb) {
        tvb_composite_finalize(composite_tvb);
    }
    LZ4F_freeDecompressionContext(lz4_ctxt);
    if (ret == 1) {
        *decompressed_tvb = composite_tvb;
        *decompressed_offset = 0;
    }
    else {
        col_append_str(pinfo->cinfo, COL_INFO, " [lz4 decompression failed]");
    }
    return ret;
}
#else
static bool
decompress_lz4(tvbuff_t *tvb _U_, packet_info *pinfo, int offset _U_, uint32_t length _U_, tvbuff_t **decompressed_tvb _U_, int *decompressed_offset _U_)
{
    col_append_str(pinfo->cinfo, COL_INFO, " [lz4 decompression unsupported]");
    return false;
}
#endif /* HAVE_LZ4FRAME_H */

#ifdef HAVE_SNAPPY
static bool
decompress_snappy(tvbuff_t *tvb, packet_info *pinfo, int offset, uint32_t length, tvbuff_t **decompressed_tvb, int *decompressed_offset)
{
    tvbuff_t *composite_tvb = NULL;
    bool ret = false;

    if (tvb_memeql(tvb, offset, kafka_xerial_header, sizeof(kafka_xerial_header)) == 0) {

        /* xerial framing format */
        uint32_t chunk_size, pos = 16;
        int count = 0;

        while (pos < length && count < MAX_LOOP_ITERATIONS) {
            tvbuff_t *decompressed_chunk_tvb;

            if (pos > length-4) {
                // XXX - this is presumably an error, as the chunk size
                // doesn't fully fit in the data, so an error should be
                // reported.
                goto end;
            }
            chunk_size = tvb_get_ntohl(tvb, offset+pos);
            pos += 4;
            if (chunk_size > length) {
                // XXX - this is presumably an error, as the chunk to be
                // decompressed doesn't fully fit in the data, so an error
                // should be reported.
                goto end;
            }
            if (pos > length-chunk_size) {
                // XXX - this is presumably an error, as the chunk to be
                // decompressed doesn't fully fit in the data, so an error
                // should be reported.
                goto end;
            }
            decompressed_chunk_tvb = tvb_child_uncompress_snappy(tvb, tvb, offset+pos, chunk_size);
            if (decompressed_chunk_tvb == NULL) {
                goto end;
            }
            if (!composite_tvb) {
                composite_tvb = tvb_new_composite();
            }
            tvb_composite_append(composite_tvb, decompressed_chunk_tvb);
            pos += chunk_size;
            count++;
            DISSECTOR_ASSERT_HINT(count < MAX_LOOP_ITERATIONS, "MAX_LOOP_ITERATIONS exceeded");
        }

    } else {

        /* unframed format */
        *decompressed_tvb = tvb_child_uncompress_snappy(tvb, tvb, offset, length);
        if (*decompressed_tvb == NULL) {
            goto end;
        }
        *decompressed_offset = 0;

    }
    ret = true;
end:
    if (composite_tvb) {
        tvb_composite_finalize(composite_tvb);
        if (ret) {
            *decompressed_tvb = composite_tvb;
            *decompressed_offset = 0;
        }
    }
    if (!ret) {
        col_append_str(pinfo->cinfo, COL_INFO, " [snappy decompression failed]");
    }
    return ret;
}
#else
static bool
decompress_snappy(tvbuff_t *tvb _U_, packet_info *pinfo, int offset _U_, int length _U_, tvbuff_t **decompressed_tvb _U_, int *decompressed_offset _U_)
{
    col_append_str(pinfo->cinfo, COL_INFO, " [snappy decompression unsupported]");
    return false;
}
#endif /* HAVE_SNAPPY */

#ifdef HAVE_ZSTD
static bool
decompress_zstd(tvbuff_t *tvb, packet_info *pinfo, int offset, uint32_t length, tvbuff_t **decompressed_tvb, int *decompressed_offset)
{
    *decompressed_tvb = tvb_child_uncompress_zstd(tvb, tvb, offset, length);
    *decompressed_offset = 0;
    if (*decompressed_tvb) {
        return true;
    } else {
        col_append_str(pinfo->cinfo, COL_INFO, " [zstd decompression failed] ");
        return false;
    }
}
#else
static bool
decompress_zstd(tvbuff_t *tvb _U_, packet_info *pinfo, int offset _U_, uint32_t length _U_, tvbuff_t **decompressed_tvb _U_, int *decompressed_offset _U_)
{
    col_append_str(pinfo->cinfo, COL_INFO, " [zstd compression unsupported]");
    return false;
}
#endif /* HAVE_ZSTD */

// Max is currently 2^22 in
// https://github.com/apache/kafka/blob/trunk/clients/src/main/java/org/apache/kafka/common/compress/KafkaLZ4BlockOutputStream.java
#define MAX_DECOMPRESSION_SIZE (1 << 22)
static bool
decompress(tvbuff_t *tvb, packet_info *pinfo, int offset, uint32_t length, int codec, tvbuff_t **decompressed_tvb, int *decompressed_offset)
{
    if (length > MAX_DECOMPRESSION_SIZE) {
        expert_add_info(pinfo, NULL, &ei_kafka_bad_decompression_length);
        return false;
    }
    if (length == 0) {
        expert_add_info(pinfo, NULL, &ei_kafka_zero_decompression_length);
        return false;
    }
    switch (codec) {
        case KAFKA_MESSAGE_CODEC_SNAPPY:
            return decompress_snappy(tvb, pinfo, offset, length, decompressed_tvb, decompressed_offset);
        case KAFKA_MESSAGE_CODEC_LZ4:
            return decompress_lz4(tvb, pinfo, offset, length, decompressed_tvb, decompressed_offset);
        case KAFKA_MESSAGE_CODEC_ZSTD:
            return decompress_zstd(tvb, pinfo, offset, length, decompressed_tvb, decompressed_offset);
        case KAFKA_MESSAGE_CODEC_GZIP:
            return decompress_gzip(tvb, pinfo, offset, length, decompressed_tvb, decompressed_offset);
        case KAFKA_MESSAGE_CODEC_NONE:
            return decompress_none(tvb, pinfo, offset, length, decompressed_tvb, decompressed_offset);
        default:
            col_append_str(pinfo->cinfo, COL_INFO, " [unsupported compression type]");
            return false;
    }
}

/*
 * Function: dissect_kafka_message_old
 * ---------------------------------------------------
 * Handles decoding of pre-0.11 message format. In the old format
 * only the message payload was the subject of compression
 * and the batches were special kind of message payload.
 *
 * https://kafka.apache.org/0100/documentation/#messageformat
 *
 * tvb: actual data buffer
 * pinfo: packet information
 * tree: protocol information tree to append the item
 * hf_item: protocol information item descriptor index
 * offset: pointer to the message
 * end_offset: last possible offset in this batch
 *
 * returns: pointer to the next message/batch
 */
static int
// NOLINTNEXTLINE(misc-no-recursion)
dissect_kafka_message_old(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset, int end_offset _U_)
{
    proto_item  *message_ti;
    proto_tree  *subtree;
    tvbuff_t    *decompressed_tvb;
    int         decompressed_offset;
    int         start_offset = offset;
    int         bytes_offset;
    int8_t      magic_byte;
    uint8_t     codec;
    uint32_t    message_size;
    uint32_t    length;

    message_size = tvb_get_uint32(tvb, start_offset + 8, ENC_BIG_ENDIAN);

    subtree = proto_tree_add_subtree(tree, tvb, start_offset, message_size + 12, ett_kafka_message, &message_ti, "Message");

    offset = dissect_kafka_int64(subtree, hf_kafka_offset, tvb, pinfo, offset, NULL);

    offset = dissect_kafka_int32(subtree, hf_kafka_message_size, tvb, pinfo, offset, NULL);

    offset = dissect_kafka_int32(subtree, hf_kafka_message_crc, tvb, pinfo, offset, NULL);

    offset = dissect_kafka_int8(subtree, hf_kafka_message_magic, tvb, pinfo, offset, &magic_byte);

    /* Don't advance "offset" here: The following message timestamp type field is in the same byte as the codec. */
    (void)dissect_kafka_int8(subtree, hf_kafka_message_codec, tvb, pinfo, offset, &codec);
    codec &= KAFKA_MESSAGE_CODEC_MASK;

    offset = dissect_kafka_int8(subtree, hf_kafka_message_timestamp_type, tvb, pinfo, offset, NULL);

    if (magic_byte > 0) {
        proto_tree_add_item(subtree, hf_kafka_message_timestamp, tvb, offset, 8, ENC_TIME_MSECS|ENC_BIG_ENDIAN);
        offset += 8;
    }

    bytes_offset = dissect_kafka_regular_bytes(subtree, hf_kafka_message_key, tvb, pinfo, offset, NULL, NULL);
    if (bytes_offset > offset) {
        offset = bytes_offset;
    } else {
        expert_add_info(pinfo, message_ti, &ei_kafka_bad_bytes_length);
        return offset;
    }

    /*
     * depending on the compression codec, the payload is the actual message payload (codes=none)
     * or compressed set of messages (otherwise). In the new format (since Kafka 1.0) there
     * is no such duality.
     */
    if (codec == 0) {
        bytes_offset = dissect_kafka_regular_bytes(subtree, hf_kafka_message_value, tvb, pinfo, offset, NULL, &length);
        if (bytes_offset > offset) {
            offset = bytes_offset;
        } else {
            expert_add_info(pinfo, message_ti, &ei_kafka_bad_bytes_length);
            return offset;
        }
    } else {
        length = tvb_get_ntohl(tvb, offset);
        offset += 4;
        if (decompress(tvb, pinfo, offset, length, codec, &decompressed_tvb, &decompressed_offset)==1) {
            add_new_data_source(pinfo, decompressed_tvb, "Decompressed content");
            show_compression_reduction(tvb, subtree, length, tvb_captured_length(decompressed_tvb));
            dissect_kafka_regular_message_set(decompressed_tvb, pinfo, subtree, decompressed_offset,
                                              tvb_reported_length_remaining(decompressed_tvb, decompressed_offset),
                                              codec);
            offset += length;
        } else {
            proto_item_append_text(subtree, " [Cannot decompress records]");
        }
    }

    proto_item_set_end(message_ti, tvb, offset);

    return offset;
}

/*
 * Function: dissect_kafka_message_new
 * ---------------------------------------------------
 * Handles decoding of the new message format. In the new format
 * there is no difference between compressed and plain batch.
 *
 * https://kafka.apache.org/documentation/#messageformat
 *
 * tvb: actual data buffer
 * pinfo: packet information
 * tree: protocol information tree to append the item
 * hf_item: protocol information item descriptor index
 * offset: pointer to the message
 * end_offset: last possible offset in this batch
 *
 * returns: pointer to the next message/batch
 */
static int
// NOLINTNEXTLINE(misc-no-recursion)
dissect_kafka_message_new(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset, int end_offset _U_)
{
    proto_item *batch_ti;
    proto_tree *subtree;
    int         start_offset = offset;
    int8_t      magic_byte;
    uint16_t    codec;
    uint32_t    message_size;
    uint32_t    count, i, length;
    uint64_t    base_offset, first_timestamp;

    tvbuff_t    *decompressed_tvb;
    int         decompressed_offset;

    message_size = tvb_get_uint32(tvb, start_offset + 8, ENC_BIG_ENDIAN);

    subtree = proto_tree_add_subtree(tree, tvb, start_offset, message_size + 12, ett_kafka_batch, &batch_ti, "Record Batch");

    offset = dissect_kafka_int64(subtree, hf_kafka_offset, tvb, pinfo, offset, &base_offset);

    offset = dissect_kafka_int32(subtree, hf_kafka_message_size, tvb, pinfo, offset, NULL);

    offset = dissect_kafka_int32(subtree, hf_kafka_leader_epoch, tvb, pinfo, offset, NULL);

    offset = dissect_kafka_int8(subtree, hf_kafka_message_magic, tvb, pinfo, offset, &magic_byte);

    if (magic_byte != 2) {
        proto_item_append_text(subtree, "[Unknown message magic]");
        expert_add_info_format(pinfo, batch_ti, &ei_kafka_unknown_message_magic,
                               "message magic: %d", magic_byte);
        return start_offset + 8 /*base offset*/ + 4 /*message size*/ + message_size;
    }

    offset = dissect_kafka_int32(subtree, hf_kafka_batch_crc, tvb, pinfo, offset, NULL);

    dissect_kafka_int16(subtree, hf_kafka_batch_codec, tvb, pinfo, offset, &codec);
    codec &= KAFKA_MESSAGE_CODEC_MASK;
    dissect_kafka_int16(subtree, hf_kafka_batch_timestamp_type, tvb, pinfo, offset, NULL);
    dissect_kafka_int16(subtree, hf_kafka_batch_transactional, tvb, pinfo, offset, NULL);
    dissect_kafka_int16(subtree, hf_kafka_batch_control_batch, tvb, pinfo, offset, NULL);
    // next octet is reserved
    offset += 2;

    offset = dissect_kafka_int32(subtree, hf_kafka_batch_last_offset_delta, tvb, pinfo, offset, NULL);

    offset = dissect_kafka_int64(subtree, hf_kafka_batch_first_timestamp, tvb, pinfo, offset, &first_timestamp);
    offset = dissect_kafka_int64(subtree, hf_kafka_batch_last_timestamp, tvb, pinfo, offset, NULL);

    offset = dissect_kafka_int64(subtree, hf_kafka_producer_id, tvb, pinfo, offset, NULL);
    offset = dissect_kafka_int16(subtree, hf_kafka_producer_epoch, tvb, pinfo, offset, NULL);

    offset = dissect_kafka_int32(subtree, hf_kafka_batch_base_sequence, tvb, pinfo, offset, NULL);

    offset = dissect_kafka_int32(subtree, hf_kafka_batch_size, tvb, pinfo, offset, &count);

    length = start_offset + 8 /*base offset*/ + 4 /*message size*/ + message_size - offset;

    if (decompress(tvb, pinfo, offset, length, codec, &decompressed_tvb, &decompressed_offset)==1) {
        if (codec != 0) {
            add_new_data_source(pinfo, decompressed_tvb, "Decompressed Records");
            show_compression_reduction(tvb, subtree, length, tvb_captured_length(decompressed_tvb));
        }
        for (i=0;i<count;i++) {
            decompressed_offset = dissect_kafka_record(decompressed_tvb, pinfo, subtree, decompressed_offset, base_offset, first_timestamp);
        }
    } else {
        proto_item_append_text(subtree, " [Cannot decompress records]");
    }

    return start_offset + 8 /*base offset*/ + 4 /*message size*/ + message_size;
}

static int
// NOLINTNEXTLINE(misc-no-recursion)
dissect_kafka_message(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset, int end_offset)
{
    int8_t      magic_byte;
    uint32_t    message_size;

    if (offset + 12 > end_offset) {
        // in this case we deal with truncated message, where the size part may be also truncated
        // actually we may add truncated info
        proto_tree_add_item(tree, hf_kafka_truncated_content, tvb, offset, end_offset-offset, ENC_NA);
        return end_offset;
    }
    message_size = tvb_get_uint32(tvb, offset + 8, ENC_BIG_ENDIAN);
    if (offset + 12 + message_size > (uint32_t)end_offset) {
        // in this case we deal with truncated message, where the truncation point falls somewhere
        // in the message body
        proto_tree_add_item(tree, hf_kafka_truncated_content, tvb, offset, end_offset-offset, ENC_NA);
        return end_offset;
    }

    magic_byte = tvb_get_uint8(tvb, offset + 16);
    int message_offset = 0;
    increment_dissection_depth(pinfo);
    if (magic_byte < 2) {
        message_offset = dissect_kafka_message_old(tvb, pinfo, tree, offset, end_offset);
    } else {
        message_offset = dissect_kafka_message_new(tvb, pinfo, tree, offset, end_offset);
    }
    decrement_dissection_depth(pinfo);
    return message_offset;
}

static int
// NOLINTNEXTLINE(misc-no-recursion)
dissect_kafka_regular_message_set(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset, unsigned len, uint8_t codec)
{
    proto_item *ti;
    proto_tree *subtree;
    int         end_offset = offset + len;

    subtree = proto_tree_add_subtree(tree, tvb, offset, -1, ett_kafka_message_set, &ti, "Message Set");
    /* If set came from a compressed message, make it obvious in tree root */
    if (codec != KAFKA_MESSAGE_CODEC_NONE) {
        proto_item_append_text(subtree, " [from compressed %s message]", val_to_str_const(codec, kafka_message_codecs, "Unknown"));
    }

    while (offset < end_offset) {
        offset = dissect_kafka_message(tvb, pinfo, subtree, offset, end_offset);
    }

    if (offset != end_offset) {
        expert_add_info(pinfo, ti, &ei_kafka_bad_message_set_length);
    }

    proto_item_set_end(ti, tvb, offset);

    return offset;
}

static int
dissect_kafka_message_set(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset, unsigned flexible, uint8_t codec)
{
    unsigned   len;
    uint64_t length;
    proto_item *subti;

    if (flexible) {
        len = tvb_get_varint(tvb, offset, FT_VARINT_MAX_LEN, &length, ENC_VARINT_PROTOBUF);

        if (len == 0) {
            // this message set is malformed
            proto_tree_add_subtree(tree, tvb, offset, -1, ett_kafka_message_set, &subti, "Message Set");
            expert_add_info(pinfo, subti, &ei_kafka_bad_varint);
            proto_item_set_end(subti, tvb, offset);
            return tvb_captured_length(tvb);
        }

        offset = offset + len;

        if (length > 0) {
            offset = dissect_kafka_regular_message_set(tvb, pinfo, tree, offset, (int)length - 1, codec);
        }
    }
    else {
        len = tvb_get_ntohl(tvb, offset);
        offset += 4;

        if (len > 0) {
            offset = dissect_kafka_regular_message_set(tvb, pinfo, tree, offset, len, codec);
        }
    }

    return offset;
}

/* Tagged fields support (since Kafka 2.4) */

/*
 * Other that in dissect_kafka_compacted_bytes the length is given as unsigned varint.
 */
static int
dissect_kafka_tagged_field_data(proto_tree *tree, int hf_item, tvbuff_t *tvb, packet_info *pinfo, int offset,
                                int *p_offset, int *p_len)
{
    proto_item *pi;

    uint64_t length;
    int32_t len;

    len = tvb_get_varint(tvb, offset, FT_VARINT_MAX_LEN, &length, ENC_VARINT_PROTOBUF);
    if (len == 0) length = 0;

    pi = proto_tree_add_item(tree, hf_item, tvb, offset+len, (int)length, ENC_NA);
    if (len == 0) {
        expert_add_info(pinfo, pi, &ei_kafka_bad_varint);
        if (p_offset) {
            *p_offset = 0;
        }
        if (p_len) {
            *p_len = 0;
        }
        return tvb_captured_length(tvb);
    }

    offset = offset + len + (int)length;
    if (p_offset != NULL) *p_offset = offset + len;
    if (p_len != NULL) *p_len = (int)length;

    return offset;
}

static int
dissect_kafka_tagged_field(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset,
                              kafka_api_version_t api_version _U_)
{
    proto_item *subti;
    proto_tree *subtree;

    subtree = proto_tree_add_subtree(tree, tvb, offset, -1,
                                     ett_kafka_tagged_field,
                                     &subti, "Field");

    offset = dissect_kafka_varuint(subtree, hf_kafka_tagged_field_tag, tvb, pinfo, offset, NULL);

    offset = dissect_kafka_tagged_field_data(subtree, hf_kafka_tagged_field_data, tvb, pinfo, offset, NULL, NULL);

    proto_item_set_end(subti, tvb, offset);

    return offset;

}

static int
dissect_kafka_tagged_fields(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset,
                               kafka_api_version_t api_version _U_)
{
    int64_t count;
    unsigned len;
    proto_item *subti;
    proto_tree *subtree;

    subtree = proto_tree_add_subtree(tree, tvb, offset, -1,
                                     ett_kafka_tagged_fields,
                                     &subti, "Tagged fields");

    len = tvb_get_varint(tvb, offset, FT_VARINT_MAX_LEN, &count, ENC_VARINT_PROTOBUF);
    if (len == 0) {
        expert_add_info(pinfo, subtree, &ei_kafka_bad_varint);
        return tvb_captured_length(tvb);
   }
    offset += len;

    /*
     * Contrary to compact arrays, tagged fields store just count
     * https://cwiki.apache.org/confluence/display/KAFKA/KIP-482%3A+The+Kafka+Protocol+should+Support+Optional+Tagged+Fields
     */
    offset = dissect_kafka_array_elements(subtree, tvb, pinfo, offset, api_version, &dissect_kafka_tagged_field, (int32_t)count);

    proto_item_set_end(subti, tvb, offset);

    return offset;
}

/* OFFSET FETCH REQUEST/RESPONSE */

static int
dissect_kafka_partition_id_ret(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, int offset,
                           kafka_partition_t *p_partition)
{
    proto_tree_add_item(tree, hf_kafka_partition_id, tvb, offset, 4, ENC_BIG_ENDIAN);
    if (p_partition != NULL) {
        *p_partition = tvb_get_ntohl(tvb, offset);
    }
    offset += 4;

    return offset;
}

static int
dissect_kafka_partition_id(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset,
                           kafka_api_version_t api_version _U_)
{
    return dissect_kafka_partition_id_ret(tvb, pinfo, tree, offset, NULL);
}

static int
dissect_kafka_offset_ret(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, int offset,
                     kafka_offset_t *p_offset)
{
    proto_tree_add_item(tree, hf_kafka_offset, tvb, offset, 8, ENC_BIG_ENDIAN);
    if (p_offset != NULL) {
        *p_offset = tvb_get_ntoh64(tvb, offset);
    }
    offset += 8;

    return offset;
}

static int
dissect_kafka_offset(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset,
                     kafka_api_version_t api_version _U_)
{
    return dissect_kafka_offset_ret(tvb, pinfo, tree, offset, NULL);
}

static int
dissect_kafka_leader_epoch(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, int offset,
                     kafka_api_version_t api_version _U_)
{
    proto_tree_add_item(tree, hf_kafka_leader_epoch, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;

    return offset;
}

static int
dissect_kafka_offset_time(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, int offset,
                          kafka_api_version_t api_version _U_)
{
    proto_item *ti;
    int64_t message_offset_time;

    message_offset_time = tvb_get_ntoh64(tvb, offset);

    ti = proto_tree_add_item(tree, hf_kafka_offset_time, tvb, offset, 8, ENC_BIG_ENDIAN);
    offset += 8;

    // The query for offset at given time takes the time in milliseconds since epoch.
    // It has two additional special values:
    // * -1 - the latest offset (to consume new messages only)
    // * -2 - the oldest offset (to consume all available messages)
    if (message_offset_time == -1) {
        proto_item_append_text(ti, " (latest)");
    } else if (message_offset_time == -2) {
        proto_item_append_text(ti, " (earliest)");
    }

    return offset;
}

static int
dissect_kafka_offset_fetch_request_topic(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset,
                                         kafka_api_version_t api_version)
{
    proto_tree *subtree, *subsubtree;
    proto_item *subti, *subsubti;
    int32_t    count = 0;
    int topic_start, topic_len;

    subtree = proto_tree_add_subtree(tree, tvb, offset, -1, ett_kafka_topic, &subti, "Topic");

    offset = dissect_kafka_string(subtree, hf_kafka_topic_name, tvb, pinfo, offset, api_version >= 6, &topic_start, &topic_len);

    subsubtree = proto_tree_add_subtree(subtree, tvb, offset, -1, ett_kafka_topic, &subsubti, "Partition IDs");
    offset = dissect_kafka_array(subsubtree, tvb, pinfo, offset, api_version >= 6, api_version, &dissect_kafka_partition_id, &count);
    proto_item_set_end(subsubti, tvb, offset);

    if (api_version >= 6) {
        offset = dissect_kafka_tagged_fields(tvb, pinfo, subtree, offset, 0);
    }

    proto_item_set_end(subti, tvb, offset);
    proto_item_append_text(subti, " (Topic: %s, Partitions: %u)",
                           tvb_get_string_enc(pinfo->pool, tvb, topic_start, topic_len, ENC_UTF_8),
                           count);

    return offset;
}

static int
dissect_kafka_offset_fetch_request_topics(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset,
                                         kafka_api_version_t api_version)
{
    proto_item *ti;
    proto_tree *subtree;
    int32_t    count = 0;

    subtree = proto_tree_add_subtree(tree, tvb, offset, -1, ett_kafka_topics, &ti, "Topics");
    offset = dissect_kafka_array(subtree, tvb, pinfo, offset, api_version >= 6, api_version,
                                 &dissect_kafka_offset_fetch_request_topic, &count);
    proto_item_set_end(ti, tvb, offset);

    if (count < 0) {
        proto_item_append_text(ti, " (all committed topics)");
    } else {
        proto_item_append_text(ti, " (%u topics)", count);
    }

    return offset;
}

static int
dissect_kafka_offset_fetch_request_group(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset,
                                         kafka_api_version_t api_version)
{
    proto_item *subti;
    proto_tree *subtree;

    subtree = proto_tree_add_subtree(tree, tvb, offset, -1, ett_kafka_group_protocols, &subti, "Group");

    /* group_id */
    if (api_version >= 8) {
        offset = dissect_kafka_string(subtree, hf_kafka_group_id, tvb, pinfo, offset, api_version >= 6, NULL, NULL);
    }

    /* member_id */
    if (api_version >= 9) {
        offset = dissect_kafka_string(subtree, hf_kafka_member_id, tvb, pinfo, offset, api_version >= 6, NULL, NULL);
    }

    /* member_epoch */
    if (api_version >= 9) {
        offset = dissect_kafka_int32(subtree, hf_kafka_member_epoch, tvb, pinfo, offset, NULL);
    }

    /* [topics] */
    if (api_version >= 8) {
        offset = dissect_kafka_offset_fetch_request_topics(tvb, pinfo, subtree, offset, api_version);
    }

    if (api_version >= 6) {
        offset = dissect_kafka_tagged_fields(tvb, pinfo, subtree, offset, 0);
    }

    proto_item_set_end(subti, tvb, offset);

    return offset;
}

static int
dissect_kafka_offset_fetch_request(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset,
                                   kafka_api_version_t api_version)
{
    proto_item *subti;
    proto_tree *subtree;

    /* In versions 0-7, topic information is an array attached to the root message object.
     * In version 8, topic information is moved to a groups array attached to the root message object. Topic fields
     * haven't changed; topics have just been moved down a level in the object tree. */
    if (api_version >= 0 && api_version <= 7) {
        offset = dissect_kafka_string(tree, hf_kafka_consumer_group, tvb, pinfo, offset, api_version >=6, NULL, NULL);

        offset = dissect_kafka_offset_fetch_request_topics(tvb, pinfo, tree, offset, api_version);
    }

    if (api_version >= 8) {
        subtree = proto_tree_add_subtree(tree, tvb, offset, -1, ett_kafka_group_protocols, &subti, "Groups");
        offset = dissect_kafka_array(subtree, tvb, pinfo, offset, api_version >= 6, api_version,
                                     &dissect_kafka_offset_fetch_request_group, NULL);
        proto_item_set_end(subti, tvb, offset);
    }

    if (api_version >= 7) {
        proto_tree_add_item(tree, hf_kafka_require_stable_offset, tvb, offset, 1, ENC_NA);
        offset += 1;
    }

    if (api_version >= 6) {
        offset = dissect_kafka_tagged_fields(tvb, pinfo, tree, offset, 0);
    }

    return offset;
}

static int
dissect_kafka_error_ret(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset,
                        kafka_error_t *ret)
{
    kafka_error_t error = (kafka_error_t) tvb_get_ntohs(tvb, offset);
    proto_tree_add_item(tree, hf_kafka_error, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    /* Show error in Info column */
    if (error != 0) {
        col_append_fstr(pinfo->cinfo, COL_INFO,
                        " [%s] ", kafka_error_to_str(error));
    }

    if (ret) {
        *ret = error;
    }

    return offset;
}

static int
dissect_kafka_error(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset)
{
    return dissect_kafka_error_ret(tvb, pinfo, tree, offset, NULL);
}

static int
dissect_kafka_throttle_time(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, int offset)
{
    proto_tree_add_item(tree, hf_kafka_throttle_time, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;
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

    subtree = proto_tree_add_subtree(tree, tvb, offset, -1, ett_kafka_partition, &ti, "Partition");

    offset = dissect_kafka_partition_id_ret(tvb, pinfo, subtree, offset, &packet_values.partition_id);
    offset = dissect_kafka_offset_ret(tvb, pinfo, subtree, offset, &packet_values.offset);

    if (api_version >= 5) {
        offset = dissect_kafka_leader_epoch(tvb, pinfo, subtree, offset, api_version);
    }

    offset = dissect_kafka_string(subtree, hf_kafka_metadata, tvb, pinfo, offset, api_version >= 6, NULL, NULL);

    offset = dissect_kafka_error(tvb, pinfo, subtree, offset);

    if (packet_values.offset==-1) {
        proto_item_append_text(ti, " (ID=%u, Offset=None)",
                               packet_values.partition_id);
    } else {
        proto_item_append_text(ti, " (ID=%u, Offset=%" PRIi64 ")",
                               packet_values.partition_id, packet_values.offset);
    }

    if (api_version >= 6) {
        offset = dissect_kafka_tagged_fields(tvb, pinfo, subtree, offset, 0);
    }

    proto_item_set_end(ti, tvb, offset);

    return offset;
}

static int
dissect_kafka_offset_fetch_response_topic(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset,
                                          kafka_api_version_t api_version)
{
    proto_item *subti, *subsubti;
    proto_tree *subtree, *subsubtree;
    int topic_start, topic_len;
    int count = 0;

    subtree = proto_tree_add_subtree(tree, tvb, offset, -1, ett_kafka_topic, &subti, "Topic");

    offset = dissect_kafka_string(subtree, hf_kafka_topic_name, tvb, pinfo, offset, api_version >= 6, &topic_start, &topic_len);

    subsubtree = proto_tree_add_subtree(subtree, tvb, offset, -1, ett_kafka_topic, &subsubti, "Partition IDs");
    offset = dissect_kafka_array(subsubtree, tvb, pinfo, offset, api_version >= 6, api_version,
                                 &dissect_kafka_offset_fetch_response_partition, &count);
    proto_item_set_end(subsubti, tvb, offset);

    if (api_version >= 6) {
        offset = dissect_kafka_tagged_fields(tvb, pinfo, subtree, offset, 0);
    }

    proto_item_set_end(subti, tvb, offset);
    proto_item_append_text(subti, " (Topic: %s, Partitions: %u)",
                           tvb_get_string_enc(pinfo->pool, tvb, topic_start, topic_len, ENC_UTF_8),
                           count);

    return offset;
}

static int
dissect_kafka_offset_fetch_response_group(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset,
                                          kafka_api_version_t api_version)
{
    proto_item *subti, *subsubti;
    proto_tree *subtree, *subsubtree;

    subtree = proto_tree_add_subtree(tree, tvb, offset, -1, ett_kafka_topics, &subti, "Group");

    /* group_id */
    offset = dissect_kafka_string(subtree, hf_kafka_group_id, tvb, pinfo, offset, api_version >= 6, NULL, NULL);

    /* [topics] */
    subsubtree = proto_tree_add_subtree(subtree, tvb, offset, -1, ett_kafka_topics, &subsubti, "Topics");
    offset = dissect_kafka_array(subsubtree, tvb, pinfo, offset, api_version >= 6, api_version,
                                 &dissect_kafka_offset_fetch_response_topic, NULL);
    proto_item_set_end(subsubti, tvb, offset);

    /* error_code */
    offset = dissect_kafka_error(tvb, pinfo, subtree, offset);

    if (api_version >= 6) {
        offset = dissect_kafka_tagged_fields(tvb, pinfo, subtree, offset, 0);
    }

    proto_item_set_end(subti, tvb, offset);

    return offset;
}

static int
dissect_kafka_offset_fetch_response(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset,
                                    kafka_api_version_t api_version)
{
    proto_item *subti;
    proto_tree *subtree;
    int count = 0;

    if (api_version >= 3) {
        offset = dissect_kafka_throttle_time(tvb, pinfo, tree, offset);
    }

    /* In versions 0-7, topic information is an array attached to the root message object.
     * In version 8, topic information is moved to a groups array attached to the root message object. Topic fields
     * haven't changed; topics have just been moved down a level in the object tree. */
    if (api_version >= 0 && api_version <= 7) {
        subtree = proto_tree_add_subtree(tree, tvb, offset, -1, ett_kafka_topics, &subti, "Topics");
        offset = dissect_kafka_array(subtree, tvb, pinfo, offset, api_version >= 6, api_version,
                                     &dissect_kafka_offset_fetch_response_topic, &count);
        proto_item_set_end(subti, tvb, offset);
        proto_item_append_text(subti, " (%u topics)", count);
    }

    if (api_version >= 2 && api_version <= 7) {
        offset = dissect_kafka_error(tvb, pinfo, tree, offset);
    }

    if (api_version >= 8) {
        subtree = proto_tree_add_subtree(tree, tvb, offset, -1, ett_kafka_group_protocols, &subti,
                                         "Groups");
        offset = dissect_kafka_array(subtree, tvb, pinfo, offset, api_version >= 6, api_version,
                                     &dissect_kafka_offset_fetch_response_group, NULL);
        proto_item_set_end(subti, tvb, offset);
    }

    if (api_version >= 6) {
        offset = dissect_kafka_tagged_fields(tvb, pinfo, tree, offset, 0);
    }

    return offset;
}

/* METADATA REQUEST/RESPONSE */

static int
dissect_kafka_metadata_request_topic(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset,
                                     kafka_api_version_t api_version _U_)
{
    proto_item *ti;
    proto_tree *subtree;

    subtree = proto_tree_add_subtree(tree, tvb, offset, -1, ett_kafka_topic, &ti, "Topic");

    if (api_version >= 10) {
        offset = dissect_kafka_uuid(tree, hf_kafka_topic_id, tvb, pinfo, offset);
    }

    offset = dissect_kafka_string(subtree, hf_kafka_topic_name, tvb, pinfo, offset, api_version >= 9, NULL, NULL);

    if (api_version >= 9) {
        offset = dissect_kafka_tagged_fields(tvb, pinfo, subtree, offset, 0);
    }

    proto_item_set_end(ti, tvb, offset);

    return offset;
}

static int
dissect_kafka_metadata_request(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset,
                               kafka_api_version_t api_version)
{
    offset = dissect_kafka_array(tree, tvb, pinfo, offset, api_version >= 9, api_version,
                                 &dissect_kafka_metadata_request_topic, NULL);

    if (api_version >= 4) {
        proto_tree_add_item(tree, hf_kafka_allow_auto_topic_creation, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset += 1;
    }

    if (api_version >= 8 && api_version <= 10) {
        proto_tree_add_item(tree, hf_kafka_include_cluster_authorized_ops, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset += 1;
    }

    if (api_version >= 8) {
        proto_tree_add_item(tree, hf_kafka_include_topic_authorized_ops, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset += 1;
    }

    if (api_version >= 9) {
        offset = dissect_kafka_tagged_fields(tvb, pinfo, tree, offset, 0);
    }

    return offset;
}

static int
dissect_kafka_metadata_broker(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset,
                              kafka_api_version_t api_version)
{
    proto_item *ti;
    proto_tree *subtree;
    uint32_t    nodeid;
    int         host_start, host_len;
    uint32_t    broker_port;

    subtree = proto_tree_add_subtree(tree, tvb, offset, -1, ett_kafka_broker, &ti, "Broker");

    nodeid = tvb_get_ntohl(tvb, offset);
    proto_tree_add_item(subtree, hf_kafka_broker_nodeid, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;

    offset = dissect_kafka_string(subtree, hf_kafka_broker_host, tvb, pinfo, offset, api_version >= 9, &host_start, &host_len);

    broker_port = tvb_get_ntohl(tvb, offset);
    proto_tree_add_item(subtree, hf_kafka_broker_port, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;

    if (api_version >= 1) {
        offset = dissect_kafka_string(subtree, hf_kafka_rack, tvb, pinfo, offset, api_version >= 9, NULL, NULL);
    }

    if (api_version >= 9) {
        offset = dissect_kafka_tagged_fields(tvb, pinfo, subtree, offset, 0);
    }

    proto_item_append_text(ti, " (node %u: %s:%u)",
                           nodeid,
                           tvb_get_string_enc(pinfo->pool, tvb,
                           host_start, host_len, ENC_UTF_8),
                           broker_port);
    proto_item_set_end(ti, tvb, offset);

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
dissect_kafka_metadata_offline(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, int offset,
                           kafka_api_version_t api_version _U_)
{
    proto_tree_add_item(tree, hf_kafka_offline, tvb, offset, 4, ENC_BIG_ENDIAN);
    return offset + 4;
}

static int
dissect_kafka_metadata_partition(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset,
                                 kafka_api_version_t api_version)
{
    proto_item *ti, *subti;
    proto_tree *subtree, *subsubtree;
    kafka_partition_t partition;

    subtree = proto_tree_add_subtree(tree, tvb, offset, -1, ett_kafka_partition, &ti, "Partition");

    offset = dissect_kafka_error(tvb, pinfo, subtree, offset);

    offset = dissect_kafka_partition_id_ret(tvb, pinfo, subtree, offset, &partition);

    proto_tree_add_item(subtree, hf_kafka_leader_id, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;

    if (api_version >= 7) {
        proto_tree_add_item(subtree, hf_kafka_leader_epoch, tvb, offset, 4, ENC_BIG_ENDIAN);
        offset += 4;
    }

    subsubtree = proto_tree_add_subtree(subtree, tvb, offset, -1, ett_kafka_replicas, &subti, "Replicas");
    offset = dissect_kafka_array(subsubtree, tvb, pinfo, offset, api_version >= 9, api_version, &dissect_kafka_metadata_replica, NULL);
    proto_item_set_end(subti, tvb, offset);

    subsubtree = proto_tree_add_subtree(subtree, tvb, offset, -1, ett_kafka_isrs, &subti, "Caught-Up Replicas");
    offset = dissect_kafka_array(subsubtree, tvb, pinfo, offset, api_version >= 9, api_version, &dissect_kafka_metadata_isr, NULL);
    proto_item_set_end(subti, tvb, offset);

    if (api_version >= 5) {
        subsubtree = proto_tree_add_subtree(subtree, tvb, offset, -1, ett_kafka_offline, &subti, "Offline Replicas");
        offset = dissect_kafka_array(subsubtree, tvb, pinfo, offset, api_version >= 9, api_version, &dissect_kafka_metadata_offline, NULL);
        proto_item_set_end(subti, tvb, offset);
    }

    if (api_version >= 9) {
        offset = dissect_kafka_tagged_fields(tvb, pinfo, subtree, offset, 0);
    }

    proto_item_set_end(ti, tvb, offset);
    proto_item_append_text(ti, " (ID=%u)", partition);

    return offset;
}

static int
dissect_kafka_metadata_topic(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset,
                             kafka_api_version_t api_version)
{
    proto_item *ti;
    proto_tree *subtree;
    int         name_start, name_length;

    subtree = proto_tree_add_subtree(tree, tvb, offset, -1, ett_kafka_topic, &ti, "Topic");

    offset = dissect_kafka_error(tvb, pinfo, subtree, offset);

    offset = dissect_kafka_string(subtree, hf_kafka_topic_name, tvb, pinfo, offset, api_version >= 9, &name_start, &name_length);

    proto_item_append_text(ti, " (%s)",
                           tvb_get_string_enc(pinfo->pool, tvb,
                           name_start, name_length, ENC_UTF_8));

    if (api_version >= 10) {
        offset = dissect_kafka_uuid(subtree, hf_kafka_topic_id, tvb, pinfo, offset);
    }

    if (api_version >= 1) {
        proto_tree_add_item(subtree, hf_kafka_is_internal, tvb, offset, 1, ENC_NA);
        offset += 1;
    }

    offset = dissect_kafka_array(subtree, tvb, pinfo, offset, api_version >= 9, api_version, &dissect_kafka_metadata_partition, NULL);

    if (api_version >= 8) {
        proto_tree_add_item(subtree, hf_kafka_topic_authorized_ops, tvb, offset, 4, ENC_BIG_ENDIAN);
        offset += 4;
    }

    if (api_version >= 9) {
        offset = dissect_kafka_tagged_fields(tvb, pinfo, subtree, offset, 0);
    }

    proto_item_set_end(ti, tvb, offset);

    return offset;
}

static int
dissect_kafka_metadata_response(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset,
                                kafka_api_version_t api_version)
{
    proto_item *ti;
    proto_tree *subtree;

    if (api_version >= 3) {
        offset = dissect_kafka_throttle_time(tvb, pinfo, tree, offset);
    }

    subtree = proto_tree_add_subtree(tree, tvb, offset, -1, ett_kafka_brokers, &ti, "Broker Metadata");
    offset = dissect_kafka_array(subtree, tvb, pinfo, offset, api_version >= 9, api_version, &dissect_kafka_metadata_broker, NULL);
    proto_item_set_end(ti, tvb, offset);

    if (api_version >= 2) {
        offset = dissect_kafka_string(tree, hf_kafka_cluster_id, tvb, pinfo, offset, api_version >= 9, NULL, NULL);
    }

    if (api_version >= 1) {
        offset = dissect_kafka_int32(tree, hf_kafka_controller_id, tvb, pinfo, offset, NULL);
    }

    subtree = proto_tree_add_subtree(tree, tvb, offset, -1, ett_kafka_topics, &ti, "Topic Metadata");
    offset = dissect_kafka_array(subtree, tvb, pinfo, offset, api_version >= 9, api_version, &dissect_kafka_metadata_topic, NULL);
    proto_item_set_end(ti, tvb, offset);

    if (api_version >= 8 && api_version <= 10) {
        offset = dissect_kafka_int32(tree, hf_kafka_cluster_authorized_ops, tvb, pinfo, offset, NULL);
    }

    if (api_version >= 9) {
        offset = dissect_kafka_tagged_fields(tvb, pinfo, tree, offset, 0);
    }

    return offset;
}

/* LEADER_AND_ISR REQUEST/RESPONSE */

static int
dissect_kafka_leader_and_isr_request_isr(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree,
                                         int offset, kafka_api_version_t api_version _U_)
{
    /* isr */
    proto_tree_add_item(tree, hf_kafka_isr, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;

    return offset;
}

static int
dissect_kafka_leader_and_isr_request_replica(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree,
                                             int offset, kafka_api_version_t api_version _U_)
{
    /* replica */
    proto_tree_add_item(tree, hf_kafka_replica, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;

    return offset;
}


static int
dissect_kafka_leader_and_isr_request_partition_state(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                                                     int offset, kafka_api_version_t api_version)
{
    proto_tree *subtree, *subsubtree;
    proto_item *subti, *subsubti;
    int topic_start, topic_len;
    kafka_partition_t partition;

    subtree = proto_tree_add_subtree(tree, tvb, offset, -1,
                                     ett_kafka_partition,
                                     &subti, "Partition");

    /* topic */
    if (api_version < 2) {
        offset = dissect_kafka_string(subtree, hf_kafka_topic_name, tvb, pinfo, offset, 0,
                                      &topic_start, &topic_len);
    }

    /* partition */
    partition = (kafka_partition_t) tvb_get_ntohl(tvb, offset);
    proto_tree_add_item(subtree, hf_kafka_partition_id, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;

    /* controller_epoch */
    proto_tree_add_item(subtree, hf_kafka_controller_epoch, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;

    /* leader */
    proto_tree_add_item(subtree, hf_kafka_leader_id, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;

    /* leader_epoch */
    proto_tree_add_item(subtree, hf_kafka_leader_epoch, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;

    /* [isr] */
    subsubtree = proto_tree_add_subtree(subtree, tvb, offset, -1,
                                        ett_kafka_isrs,
                                        &subsubti, "ISRs");
    offset = dissect_kafka_array(subsubtree, tvb, pinfo, offset, api_version >= 4, api_version,
                                 &dissect_kafka_leader_and_isr_request_isr, NULL);
    proto_item_set_end(subsubti, tvb, offset);

    /* zk_version */
    proto_tree_add_item(subtree, hf_kafka_zk_version, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;

    /* [replica] */
    subsubtree = proto_tree_add_subtree(subtree, tvb, offset, -1,
                                        ett_kafka_replicas,
                                        &subsubti, "Current Replicas");
    offset = dissect_kafka_array(subsubtree, tvb, pinfo, offset, api_version >= 4, api_version,
                                 &dissect_kafka_leader_and_isr_request_replica, NULL);
    proto_item_set_end(subsubti, tvb, offset);

    if (api_version >= 3) {
        subsubtree = proto_tree_add_subtree(subtree, tvb, offset, -1,
                                            ett_kafka_replicas,
                                            &subsubti, "Adding Replicas");
        offset = dissect_kafka_array(subsubtree, tvb, pinfo, offset, api_version >= 4, api_version,
                                     &dissect_kafka_leader_and_isr_request_replica, NULL);
        proto_item_set_end(subsubti, tvb, offset);
    }

    if (api_version >= 3) {
        subsubtree = proto_tree_add_subtree(subtree, tvb, offset, -1,
                                            ett_kafka_replicas,
                                            &subsubti, "Removing Replicas");
        offset = dissect_kafka_array(subsubtree, tvb, pinfo, offset, api_version >= 4, api_version,
                                     &dissect_kafka_leader_and_isr_request_replica, NULL);
        proto_item_set_end(subsubti, tvb, offset);
    }

    if (api_version >= 1) {
        proto_tree_add_item(subtree, hf_kafka_is_new_replica, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset += 1;
    }

    if (api_version >= 6) {
        offset = dissect_kafka_int8(subtree, hf_kafka_leader_recovery_state, tvb, pinfo, offset, NULL);
    }

    if (api_version >= 4) {
        offset = dissect_kafka_tagged_fields(tvb, pinfo, subtree, offset, 0);
    }

    proto_item_set_end(subti, tvb, offset);

    if (api_version < 2) {
        proto_item_append_text(subti, " (Topic=%s, Partition-ID=%u)",
                               tvb_get_string_enc(pinfo->pool, tvb,
                                                  topic_start, topic_len, ENC_UTF_8),
                               partition);
    } else {
        proto_item_append_text(subti, " (Partition-ID=%u)",
                               partition);
    }

    return offset;
}

static int
dissect_kafka_leader_and_isr_request_topic_state(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                                                     int offset, kafka_api_version_t api_version)
{
    proto_tree *subtree;
    proto_item *subti;
    int topic_start, topic_len;

    subtree = proto_tree_add_subtree(tree, tvb, offset, -1,
                                     ett_kafka_topic,
                                     &subti, "Topic");

    /* topic */
    offset = dissect_kafka_string(subtree, hf_kafka_topic_name, tvb, pinfo, offset, api_version >= 4,
                                  &topic_start, &topic_len);

    /* topic_id */
    if (api_version >= 5) {
        offset = dissect_kafka_uuid(subtree, hf_kafka_topic_id, tvb, pinfo, offset);
    }

    /* [partition_state] */
    offset = dissect_kafka_array(subtree, tvb, pinfo, offset, api_version >= 4, api_version,
                                 &dissect_kafka_leader_and_isr_request_partition_state, NULL);

    if (api_version >= 4) {
        offset = dissect_kafka_tagged_fields(tvb, pinfo, subtree, offset, 0);
    }

    proto_item_append_text(subti, " (Name=%s)",
                           tvb_get_string_enc(pinfo->pool, tvb,
                                              topic_start, topic_len, ENC_UTF_8));

    return offset;
}

static int
dissect_kafka_leader_and_isr_request_live_leader(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                                                 int offset, kafka_api_version_t api_version _U_)
{
    proto_item *subti;
    proto_tree *subtree;
    int32_t nodeid;
    int host_start, host_len;
    int32_t broker_port;

    subtree = proto_tree_add_subtree(tree, tvb, offset, -1, ett_kafka_broker, &subti, "Live Leader");

    /* id */
    nodeid = tvb_get_ntohl(tvb, offset);
    proto_tree_add_item(subtree, hf_kafka_broker_nodeid, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;

    /* host */
    offset = dissect_kafka_string(subtree, hf_kafka_broker_host, tvb, pinfo, offset,api_version >= 4,  &host_start, &host_len);

    /* port */
    broker_port = tvb_get_ntohl(tvb, offset);
    proto_tree_add_item(subtree, hf_kafka_broker_port, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;

    if (api_version >= 4) {
        offset = dissect_kafka_tagged_fields(tvb, pinfo, subtree, offset, 0);
    }

    proto_item_set_end(subti, tvb, offset);
    proto_item_append_text(subti, " (node %u: %s:%u)",
                           nodeid,
                           tvb_get_string_enc(pinfo->pool, tvb, host_start, host_len, ENC_UTF_8),
                           broker_port);

    return offset;
}

static int
dissect_kafka_leader_and_isr_request(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset,
                                     kafka_api_version_t api_version)
{
    int32_t controller_id;

    /* controller_id */
    controller_id = (int32_t) tvb_get_ntohl(tvb, offset);
    proto_tree_add_item(tree, hf_kafka_controller_id, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;

    /* is_kraft_controller */
    if (api_version >= 7) {
        offset = dissect_kafka_bool(tree, hf_kafka_is_kraft_controller, tvb, pinfo, offset);
    }

    /* controller_epoch */
    proto_tree_add_item(tree, hf_kafka_controller_epoch, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;

    if (api_version >= 2) {
        /* broker_epoch */
        proto_tree_add_item(tree, hf_kafka_broker_epoch, tvb, offset, 8, ENC_BIG_ENDIAN);
        offset += 8;
    }

    /* type */
    if (api_version >= 5) {
        offset = dissect_kafka_int8(tree, hf_kafka_topic_inclusion_type, tvb, pinfo, offset, NULL);
    }

    if (api_version <= 1) {
        /* [partition_state] */
        offset = dissect_kafka_array(tree, tvb, pinfo, offset, 0, api_version,
                                     &dissect_kafka_leader_and_isr_request_partition_state, NULL);
    } else {
        /* [topic_state] */
        offset = dissect_kafka_array(tree, tvb, pinfo, offset, api_version >= 4, api_version,
                                     &dissect_kafka_leader_and_isr_request_topic_state, NULL);
    }

    /* [live_leader] */
    offset = dissect_kafka_array(tree, tvb, pinfo, offset, api_version >= 4, api_version,
                                 &dissect_kafka_leader_and_isr_request_live_leader, NULL);

    if (api_version >= 4) {
        offset = dissect_kafka_tagged_fields(tvb, pinfo, tree, offset, 0);
    }

    col_append_fstr(pinfo->cinfo, COL_INFO, " (Controller-ID=%d)", controller_id);

    return offset;
}

static int
dissect_kafka_leader_and_isr_response_partition(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                                                int offset, kafka_api_version_t api_version _U_)
{
    proto_item *subti;
    proto_tree *subtree;
    int topic_start, topic_len;
    kafka_partition_t partition;
    kafka_error_t error;

    subtree = proto_tree_add_subtree(tree, tvb, offset, -1,
                                     ett_kafka_partition,
                                     &subti, "Partition");

    /* topic */
    if (api_version >= 0 && api_version <= 4) {
        offset = dissect_kafka_string(subtree, hf_kafka_topic_name, tvb, pinfo, offset, api_version >= 4, &topic_start, &topic_len);
    }

    /* partition */
    partition = (int32_t) tvb_get_ntohl(tvb, offset);
    proto_tree_add_item(subtree, hf_kafka_partition_id, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;

    /* error_code */
    offset = dissect_kafka_error_ret(tvb, pinfo, subtree, offset, &error);

    if (api_version >= 4) {
        offset = dissect_kafka_tagged_fields(tvb, pinfo, subtree, offset, 0);
    }

    proto_item_set_end(subti, tvb, offset);

    if (api_version >= 0 && api_version <= 4) {
        proto_item_append_text(subti, " (Topic=%s, Partition-ID=%u, Error=%s)",
                               tvb_get_string_enc(pinfo->pool, tvb,
                                                  topic_start, topic_len, ENC_UTF_8),
                               partition,
                               kafka_error_to_str(error));
    }

    return offset;
}

static int
dissect_kafka_leader_and_isr_response_topic_state(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                                                  int offset, kafka_api_version_t api_version)
{
    proto_tree *subtree;
    proto_item *subti;

    subtree = proto_tree_add_subtree(tree, tvb, offset, -1,
                                     ett_kafka_topic,
                                     &subti, "Topic");

    /* topic_id */
    if (api_version >= 5) {
        offset = dissect_kafka_uuid(subtree, hf_kafka_topic_id, tvb, pinfo, offset);
    }

    /* [partition_state] */
    if (api_version >= 5) {
        offset = dissect_kafka_array(subtree, tvb, pinfo, offset, api_version >= 4, api_version,
                                     &dissect_kafka_leader_and_isr_response_partition, NULL);
    }

    if (api_version >= 4) {
        offset = dissect_kafka_tagged_fields(tvb, pinfo, subtree, offset, 0);
    }

    proto_item_set_end(subti, tvb, offset);

    return offset;
}

static int
dissect_kafka_leader_and_isr_response(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset,
                                      kafka_api_version_t api_version)
{
    /* error_code */
    offset = dissect_kafka_error(tvb, pinfo, tree, offset);

    /* [partition] */
    if (api_version >= 0 && api_version <= 4) {
        offset = dissect_kafka_array(tree, tvb, pinfo, offset, api_version >= 4, api_version,
                                     &dissect_kafka_leader_and_isr_response_partition, NULL);
    }
    /* [topic] */
    else {
        offset = dissect_kafka_array(tree, tvb, pinfo, offset, api_version >= 4, api_version,
                                     &dissect_kafka_leader_and_isr_response_topic_state, NULL);
    }

    if (api_version >= 4) {
        offset = dissect_kafka_tagged_fields(tvb, pinfo, tree, offset, 0);
    }

    return offset;
}

/* STOP_REPLICA REQUEST/RESPONSE */

static int
dissect_kafka_stop_replicate_request_partition_state(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                                                     int offset, kafka_api_version_t api_version)
{
    if (api_version >= 3) {
        /* partition_id */
        offset = dissect_kafka_int32(tree, hf_kafka_partition_id, tvb, pinfo, offset, NULL);

        /* leader_epoch */
        offset = dissect_kafka_int32(tree, hf_kafka_leader_epoch, tvb, pinfo, offset, NULL);

        /* delete_partition */
        offset = dissect_kafka_bool(tree, hf_kafka_delete_partition, tvb, pinfo, offset);
    }

    return offset;
}

static int
dissect_kafka_stop_replica_request_topic_state(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                                               int offset, kafka_api_version_t api_version)
{
    proto_item *subti, *subsubti;
    proto_tree *subtree, *subsubtree;
    int topic_start, topic_len;

    subtree = proto_tree_add_subtree(tree, tvb, offset, -1,
                                     ett_kafka_topic,
                                     &subti, "Topic");

    if (api_version >= 3) {
        /* topic */
        offset = dissect_kafka_string(subtree, hf_kafka_topic_name, tvb, pinfo, offset, api_version >= 2, &topic_start, &topic_len);

        /* [partition_states] */
        subsubtree = proto_tree_add_subtree(subtree, tvb, offset, -1,
                                            ett_kafka_partitions,
                                            &subsubti, "Partitions");
        offset = dissect_kafka_array(subsubtree, tvb, pinfo, offset, api_version >= 2, api_version,
                                     &dissect_kafka_stop_replicate_request_partition_state, NULL);

        if (api_version >= 2) {
            offset = dissect_kafka_tagged_fields(tvb, pinfo, subtree, offset, 0);
        }

        proto_item_set_end(subsubti, tvb, offset);
    }

    proto_item_set_end(subti, tvb, offset);

    if (api_version >= 3) {
        proto_item_append_text(subti, " (Topic=%s)",
                               tvb_get_string_enc(pinfo->pool, tvb,
                                                  topic_start, topic_len, ENC_UTF_8));
    }

    return offset;
}

static int
dissect_kafka_stop_replica_request_topic(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                                         int offset, kafka_api_version_t api_version)
{
    proto_item *subti, *subsubti;
    proto_tree *subtree, *subsubtree;
    int topic_start, topic_len;

    subtree = proto_tree_add_subtree(tree, tvb, offset, -1,
                                     ett_kafka_topic,
                                     &subti, "Topic");

    if (api_version >= 1 && api_version <= 2) {
        /* topic */
        offset = dissect_kafka_string(subtree, hf_kafka_topic_name, tvb, pinfo, offset, api_version >= 2, &topic_start, &topic_len);

        /* [partitions] */
        subsubtree = proto_tree_add_subtree(subtree, tvb, offset, -1,
                                            ett_kafka_partitions,
                                            &subsubti, "Partitions");
        offset = dissect_kafka_array(subsubtree, tvb, pinfo, offset, api_version >= 2, api_version,
                                     &dissect_kafka_partition_id, NULL);
        proto_item_set_end(subsubti, tvb, offset);
    }

    if (api_version >= 2) {
        offset = dissect_kafka_tagged_fields(tvb, pinfo, subtree, offset, 0);
    }

    proto_item_set_end(subti, tvb, offset);

    if (api_version >= 1 && api_version <= 2) {
        proto_item_append_text(subti, " (Topic=%s)",
                               tvb_get_string_enc(pinfo->pool, tvb,
                                                  topic_start, topic_len, ENC_UTF_8));
    }

    return offset;
}

static int
dissect_kafka_stop_replica_request_ungrouped_partition(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                                         int offset, kafka_api_version_t api_version _U_)
{
    proto_item *subti;
    proto_tree *subtree;
    int topic_start, topic_len;
    kafka_partition_t partition;

    subtree = proto_tree_add_subtree(tree, tvb, offset, -1,
                                     ett_kafka_topic,
                                     &subti, "Partition");

    /* topic */
    offset = dissect_kafka_string(subtree, hf_kafka_topic_name, tvb, pinfo, offset, 0, &topic_start, &topic_len);

    /* partition */
    partition = (int32_t) tvb_get_ntohl(tvb, offset);
    proto_tree_add_item(subtree, hf_kafka_partition_id, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;

    proto_item_set_end(subti, tvb, offset);
    proto_item_append_text(subti, " (Topic=%s, Partition-ID=%u)",
                           tvb_get_string_enc(pinfo->pool, tvb,
                                              topic_start, topic_len, ENC_UTF_8),
                           partition);

    return offset;
}

static int
dissect_kafka_stop_replica_request(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset,
                                   kafka_api_version_t api_version)
{
    proto_item *subti;
    proto_tree *subtree;
    int32_t controller_id;

    /* controller_id */
    controller_id = (int32_t) tvb_get_ntohl(tvb, offset);
    proto_tree_add_item(tree, hf_kafka_controller_id, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;

    /* is_kraft_controller */
    if (api_version >= 4) {
        offset = dissect_kafka_bool(tree, hf_kafka_is_kraft_controller, tvb, pinfo, offset);
    }

    /* controller_epoch */
    proto_tree_add_item(tree, hf_kafka_controller_epoch, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;

    /* broker_epoch */
    if (api_version >= 1) {
        proto_tree_add_item(tree, hf_kafka_broker_epoch, tvb, offset, 8, ENC_BIG_ENDIAN);
        offset += 8;
    }

    /* delete_partitions */
    if (api_version >= 0 && api_version <= 2) {
        proto_tree_add_item(tree, hf_kafka_delete_partitions, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset += 1;
    }

    /* in V1 list of topic/partition was changed to list of topics with their partitions */
    /* in V3 this was changed again to list of topics with partition states */
    if (api_version == 0) {
        /* [ungrouped_partitions] */
        subtree = proto_tree_add_subtree(tree, tvb, offset, -1,
                                         ett_kafka_partitions,
                                         &subti, "Ungrouped Partitions");
        offset = dissect_kafka_array(subtree, tvb, pinfo, offset, 0, api_version,
                                     &dissect_kafka_stop_replica_request_ungrouped_partition, NULL);
        proto_item_set_end(subti, tvb, offset);
    } else if (api_version >= 1 && api_version <= 2) {
        /* [topics] */
        subtree = proto_tree_add_subtree(tree, tvb, offset, -1,
                                         ett_kafka_topics,
                                         &subti, "Topics");
        offset = dissect_kafka_array(subtree, tvb, pinfo, offset, api_version >= 2, api_version,
                                             &dissect_kafka_stop_replica_request_topic, NULL);
        proto_item_set_end(subti, tvb, offset);
    } else {
        /* [topics] */
        subtree = proto_tree_add_subtree(tree, tvb, offset, -1,
                                         ett_kafka_topics,
                                         &subti, "Topics");
        offset = dissect_kafka_array(subtree, tvb, pinfo, offset, api_version >= 2, api_version,
                                     &dissect_kafka_stop_replica_request_topic_state, NULL);

        if (api_version >= 2) {
            offset = dissect_kafka_tagged_fields(tvb, pinfo, subtree, offset, 0);
        }

        proto_item_set_end(subti, tvb, offset);
    }

    if (api_version >= 2) {
        offset = dissect_kafka_tagged_fields(tvb, pinfo, tree, offset, 0);
    }

    col_append_fstr(pinfo->cinfo, COL_INFO, " (Controller-ID=%d)", controller_id);

    return offset;
}

static int
dissect_kafka_stop_replica_response_partition(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                                              int offset, kafka_api_version_t api_version)
{
    proto_item *subti;
    proto_tree *subtree;
    int topic_start, topic_len;
    kafka_error_t error;
    kafka_partition_t partition;

    subtree = proto_tree_add_subtree(tree, tvb, offset, -1,
                                     ett_kafka_partition,
                                     &subti, "Partition");

    /* topic */
    offset = dissect_kafka_string(subtree, hf_kafka_topic_name, tvb, pinfo, offset, api_version >= 2, &topic_start, &topic_len);

    /* partition */
    partition = (int32_t) tvb_get_ntohl(tvb, offset);
    proto_tree_add_item(subtree, hf_kafka_partition_id, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;

    /* error_code */
    offset = dissect_kafka_error_ret(tvb, pinfo, subtree, offset, &error);

    if (api_version >= 2) {
        offset = dissect_kafka_tagged_fields(tvb, pinfo, subtree, offset, 0);
    }

    proto_item_set_end(subti, tvb, offset);
    proto_item_append_text(subti, " (Topic=%s, Partition-ID=%u, Error=%s)",
                           tvb_get_string_enc(pinfo->pool, tvb,
                                              topic_start, topic_len, ENC_UTF_8),
                           partition,
                           kafka_error_to_str(error));

    return offset;
}

static int
dissect_kafka_stop_replica_response(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset,
                                    kafka_api_version_t api_version)
{
    /* error_code */
    offset = dissect_kafka_error(tvb, pinfo, tree, offset);

    /* [partition] */
    offset = dissect_kafka_array(tree, tvb, pinfo, offset, api_version >= 2, api_version,
                                 &dissect_kafka_stop_replica_response_partition, NULL);

    if (api_version >= 2) {
        offset = dissect_kafka_tagged_fields(tvb, pinfo, tree, offset, 0);
    }

    return offset;
}

/* FETCH REQUEST/RESPONSE */

static int
dissect_kafka_fetch_request_partition(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset,
                                      kafka_api_version_t api_version)
{
    proto_item *ti;
    proto_tree *subtree;
    kafka_packet_values_t packet_values;
    memset(&packet_values, 0, sizeof(packet_values));

    subtree = proto_tree_add_subtree(tree, tvb, offset, 16, ett_kafka_partition, &ti, "Partition");

    offset = dissect_kafka_partition_id_ret(tvb, pinfo, subtree, offset, &packet_values.partition_id);

    if (api_version >= 9) {
        proto_tree_add_item(subtree, hf_kafka_leader_epoch, tvb, offset, 4, ENC_BIG_ENDIAN);
        offset += 4;
    }

    offset = dissect_kafka_offset_ret(tvb, pinfo, subtree, offset, &packet_values.offset);

    if (api_version >= 12) {
        offset = dissect_kafka_int32(subtree, hf_kafka_last_fetched_epoch, tvb, pinfo, offset, NULL);
    }

    if (api_version >= 5) {
        proto_tree_add_item(subtree, hf_kafka_log_start_offset, tvb, offset, 8, ENC_BIG_ENDIAN);
        offset += 8;
    }

    proto_tree_add_item(subtree, hf_kafka_max_bytes, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;

    if (api_version >= 12) {
        offset = dissect_kafka_tagged_fields(tvb, pinfo, subtree, offset, 0);
    }

    proto_item_append_text(ti, " (ID=%u, Offset=%" PRIi64 ")",
                           packet_values.partition_id, packet_values.offset);

    return offset;
}

static int
dissect_kafka_fetch_request_topic(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset,
                                  kafka_api_version_t api_version)
{
    proto_item *subti, *subsubti;
    proto_tree *subtree, *subsubtree;
    uint32_t    count = 0;
    int         name_start, name_length;

    subtree = proto_tree_add_subtree(tree, tvb, offset, -1, ett_kafka_topic, &subti, "Topic");

    if (api_version >= 0 && api_version <= 12) {
        offset = dissect_kafka_string(subtree, hf_kafka_topic_name, tvb, pinfo, offset, api_version >= 12, &name_start, &name_length);
    }

    if (api_version >= 13) {
        offset = dissect_kafka_uuid(subtree, hf_kafka_topic_id, tvb, pinfo, offset);
    }

    subsubtree = proto_tree_add_subtree(subtree, tvb, offset, -1, ett_kafka_topic, &subsubti, "Partitions");
    offset = dissect_kafka_array(subsubtree, tvb, pinfo, offset, api_version >= 12, api_version,
                                 &dissect_kafka_fetch_request_partition, &count);
    proto_item_set_end(subsubti, tvb, offset);

    if (api_version >= 12) {
        offset = dissect_kafka_tagged_fields(tvb, pinfo, subtree, offset, 0);
    }

    proto_item_set_end(subti, tvb, offset);
    proto_item_append_text(subti, " (%u partitions)", count);

    return offset;
}

static int
dissect_kafka_fetch_request_forgottent_topic_partition(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, int offset,
                                                  kafka_api_version_t api_version _U_)
{
    proto_tree_add_item(tree, hf_kafka_forgotten_topic_partition, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;
    return offset;
}

static int
dissect_kafka_fetch_request_forgotten_topics_data(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset,
                                  kafka_api_version_t api_version)
{
    proto_item *ti;
    proto_tree *subtree;
    uint32_t    count = 0;
    int         name_start, name_length;

    subtree = proto_tree_add_subtree(tree, tvb, offset, -1, ett_kafka_request_forgotten_topic, &ti, "Fetch Request Forgotten Topic Data");

    if (api_version >= 0 && api_version <= 12) {
        offset = dissect_kafka_string(subtree, hf_kafka_forgotten_topic_name, tvb, pinfo, offset,
                                      api_version >= 12, &name_start, &name_length);
    }

    if (api_version >= 13) {
        offset = dissect_kafka_uuid(subtree, hf_kafka_forgotten_topic_id, tvb, pinfo, offset);
    }

    offset = dissect_kafka_array(subtree, tvb, pinfo, offset, api_version >= 12, api_version,
                                 &dissect_kafka_fetch_request_forgottent_topic_partition, &count);

    if (api_version >= 12) {
        offset = dissect_kafka_tagged_fields(tvb, pinfo, subtree, offset, 0);
    }

    proto_item_set_end(ti, tvb, offset);
    proto_item_append_text(ti, " (%u partitions)", count);

    return offset;
}

static int
dissect_kafka_fetch_request(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset,
                            kafka_api_version_t api_version)
{
    proto_item *subti;
    proto_tree *subtree;

    if (api_version >= 0 && api_version <= 14) {
        proto_tree_add_item(tree, hf_kafka_replica, tvb, offset, 4, ENC_BIG_ENDIAN);
        offset += 4;
    }

    proto_tree_add_item(tree, hf_kafka_max_wait_time, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;

    proto_tree_add_item(tree, hf_kafka_min_bytes, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;

    if (api_version >= 3) {
        proto_tree_add_item(tree, hf_kafka_max_bytes, tvb, offset, 4, ENC_BIG_ENDIAN);
        offset += 4;
    }

    if (api_version >= 4) {
        proto_tree_add_item(tree, hf_kafka_isolation_level, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset += 1;
    }

    if (api_version >= 7) {
        proto_tree_add_item(tree, hf_kafka_fetch_session_id, tvb, offset, 4, ENC_BIG_ENDIAN);
        offset += 4;

        proto_tree_add_item(tree, hf_kafka_fetch_session_epoch, tvb, offset, 4, ENC_BIG_ENDIAN);
        offset += 4;
    }

    subtree = proto_tree_add_subtree(tree, tvb, offset, -1, ett_kafka_request_forgotten_topic, &subti, "Topics");
    offset = dissect_kafka_array(subtree, tvb, pinfo, offset, api_version >= 12, api_version, &dissect_kafka_fetch_request_topic, NULL);
    proto_item_set_end(subti, tvb, offset);

    if (api_version >= 7) {
        subtree = proto_tree_add_subtree(tree, tvb, offset, -1, ett_kafka_request_forgotten_topic, &subti, "Forgotten Topics");
        offset = dissect_kafka_array(subtree, tvb, pinfo, offset, api_version >= 12, api_version,
                                     &dissect_kafka_fetch_request_forgotten_topics_data, NULL);
        proto_item_set_end(subti, tvb, offset);
    }

    if (api_version >= 11) {
        offset = dissect_kafka_string(tree, hf_kafka_rack, tvb, pinfo, offset, api_version >= 12, NULL, NULL);
    }

    if (api_version >= 12) {
        offset = dissect_kafka_tagged_fields(tvb, pinfo, tree, offset, 0);
    }

    return offset;
}

static int
dissect_kafka_aborted_transaction(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree,
                                  int offset, kafka_api_version_t api_version _U_)
{
    proto_item *ti;
    proto_tree *subtree;

    subtree = proto_tree_add_subtree(tree, tvb, offset, -1, ett_kafka_aborted_transaction, &ti, "Transaction");

    proto_tree_add_item(subtree, hf_kafka_producer_id, tvb, offset, 8, ENC_BIG_ENDIAN);
    offset += 8;

    proto_tree_add_item(subtree, hf_kafka_first_offset, tvb, offset, 8, ENC_BIG_ENDIAN);
    offset += 8;

    if (api_version >= 12) {
        offset = dissect_kafka_tagged_fields(tvb, pinfo, subtree, offset, 0);
    }

    proto_item_set_end(ti, tvb, offset);

    return offset;
}

static int
dissect_kafka_aborted_transactions(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                                  int offset, kafka_api_version_t api_version)
{
    proto_item *ti;
    proto_tree *subtree;

    subtree = proto_tree_add_subtree(tree, tvb, offset, -1, ett_kafka_aborted_transactions, &ti, "Aborted Transactions");

    offset = dissect_kafka_array(subtree, tvb, pinfo, offset, api_version >= 12, api_version, &dissect_kafka_aborted_transaction, NULL);

    proto_item_set_end(ti, tvb, offset);

    return offset;
}

static int
dissect_kafka_fetch_response_partition(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset,
                                       kafka_api_version_t api_version)
{
    proto_item *ti;
    proto_tree *subtree;
    kafka_packet_values_t packet_values;
    memset(&packet_values, 0, sizeof(packet_values));

    subtree = proto_tree_add_subtree(tree, tvb, offset, -1, ett_kafka_partition, &ti, "Partition");

    offset = dissect_kafka_partition_id_ret(tvb, pinfo, subtree, offset, &packet_values.partition_id);

    offset = dissect_kafka_error(tvb, pinfo, subtree, offset);

    offset = dissect_kafka_offset_ret(tvb, pinfo, subtree, offset, &packet_values.offset);

    if (api_version >= 4) {
        proto_tree_add_item(subtree, hf_kafka_last_stable_offset, tvb, offset, 8, ENC_BIG_ENDIAN);
        offset += 8;
    }

    if (api_version >= 5) {
        proto_tree_add_item(subtree, hf_kafka_log_start_offset, tvb, offset, 8, ENC_BIG_ENDIAN);
        offset += 8;
    }

    if (api_version >= 4) {
        offset = dissect_kafka_aborted_transactions(tvb, pinfo, subtree, offset, api_version);
    }

    if (api_version >= 11) {
        proto_tree_add_item(subtree, hf_kafka_replica, tvb, offset, 4, ENC_BIG_ENDIAN);
        offset += 4;
    }

    offset = dissect_kafka_message_set(tvb, pinfo, subtree, offset, api_version >= 12, KAFKA_MESSAGE_CODEC_NONE);

    if (api_version >= 12) {
        offset = dissect_kafka_tagged_fields(tvb, pinfo, subtree, offset, 0);
    }

    proto_item_set_end(ti, tvb, offset);

    proto_item_append_text(ti, " (ID=%u, Offset=%" PRIi64 ")",
                           packet_values.partition_id, packet_values.offset);

    return offset;
}

static int
dissect_kafka_fetch_response_topic(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset,
                                   kafka_api_version_t api_version)
{
    proto_item *subti, *subsubti;
    proto_tree *subtree, *subsubtree;
    uint32_t    count = 0;

    subtree = proto_tree_add_subtree(tree, tvb, offset, -1, ett_kafka_topic, &subti, "Topic");

    if (api_version >= 0 && api_version <= 12) {
        offset = dissect_kafka_string(subtree, hf_kafka_topic_name, tvb, pinfo, offset, api_version >= 12, NULL, NULL);
    }

    if (api_version >= 13) {
        offset = dissect_kafka_uuid(subtree, hf_kafka_topic_id, tvb, pinfo, offset);
    }

    subsubtree = proto_tree_add_subtree(subtree, tvb, offset, -1, ett_kafka_topic, &subsubti, "Partitions");
    offset = dissect_kafka_array(subsubtree, tvb, pinfo, offset, api_version >= 12, api_version,
                                 &dissect_kafka_fetch_response_partition, &count);
    proto_item_set_end(subsubti, tvb, offset);

    if (api_version >= 12) {
        offset = dissect_kafka_tagged_fields(tvb, pinfo, subtree, offset, 0);
    }

    proto_item_set_end(subti, tvb, offset);
    proto_item_append_text(subti, " (%u partitions)", count);

    return offset;
}

static int
dissect_kafka_fetch_response(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset,
                             kafka_api_version_t api_version)
{
    proto_item *subti;
    proto_tree *subtree;

    if (api_version >= 1) {
        offset = dissect_kafka_throttle_time(tvb, pinfo, tree, offset);
    }

    if (api_version >= 7) {
        offset = dissect_kafka_error(tvb, pinfo, tree, offset);

        proto_tree_add_item(tree, hf_kafka_fetch_session_id, tvb, offset, 4, ENC_BIG_ENDIAN);
        offset += 4;
    }

    subtree = proto_tree_add_subtree(tree, tvb, offset, -1, ett_kafka_topic, &subti, "Topics");
    offset = dissect_kafka_array(subtree, tvb, pinfo, offset, api_version >= 12, api_version, &dissect_kafka_fetch_response_topic, NULL);
    proto_item_set_end(subti, tvb, offset);

    if (api_version >= 12) {
        offset = dissect_kafka_tagged_fields(tvb, pinfo, tree, offset, 0);
    }

    return offset;
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

    subtree = proto_tree_add_subtree(tree, tvb, offset, 14, ett_kafka_partition, &ti, "Partition");

    offset = dissect_kafka_partition_id_ret(tvb, pinfo, subtree, offset, &packet_values.partition_id);

    offset = dissect_kafka_message_set(tvb, pinfo, subtree, offset, api_version >= 9, KAFKA_MESSAGE_CODEC_NONE);

    if (api_version >= 9) {
        offset = dissect_kafka_tagged_fields(tvb, pinfo, subtree, offset, 0);
    }

    proto_item_append_text(ti, " (ID=%u)", packet_values.partition_id);
    proto_item_set_end(ti, tvb, offset);

    return offset;
}

static int
dissect_kafka_produce_request_topic(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int start_offset,
                                    kafka_api_version_t api_version)
{
    proto_item *ti;
    proto_tree *subtree;
    int         offset = start_offset;
    int topic_off, topic_len;

    subtree = proto_tree_add_subtree(tree, tvb, offset, -1, ett_kafka_topic, &ti, "Topic");

    offset = dissect_kafka_string(subtree, hf_kafka_topic_name, tvb, pinfo, offset, api_version >= 9, &topic_off, &topic_len);
    offset = dissect_kafka_array(subtree, tvb, pinfo, offset, api_version >= 9, api_version,
                                 &dissect_kafka_produce_request_partition, NULL);

    if (api_version >= 9) {
        offset = dissect_kafka_tagged_fields(tvb, pinfo, subtree, offset, 0);
    }

    proto_item_append_text(ti, " (Name=%s)",
                           tvb_get_string_enc(pinfo->pool, tvb, topic_off, topic_len, ENC_UTF_8));
    proto_item_set_end(ti, tvb, offset);

    return offset;
}

static int
dissect_kafka_produce_request(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset,
                              kafka_api_version_t api_version)
{
    if (api_version >= 3) {
        offset = dissect_kafka_string(tree, hf_kafka_transactional_id, tvb, pinfo, offset, api_version >= 9, NULL, NULL);
    }

    proto_tree_add_item(tree, hf_kafka_required_acks, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    proto_tree_add_item(tree, hf_kafka_timeout, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;

    offset = dissect_kafka_array(tree, tvb, pinfo, offset, api_version >= 9, api_version,
                                 &dissect_kafka_produce_request_topic, NULL);

    if (api_version >= 9) {
        offset = dissect_kafka_tagged_fields(tvb, pinfo, tree, offset, 0);
    }

    return offset;
}

static int
dissect_kafka_produce_response_partition_record_error(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset,
                                         kafka_api_version_t api_version _U_) {
    proto_item *ti;
    proto_tree *subtree;

    subtree = proto_tree_add_subtree(tree, tvb, offset, -1, ett_kafka_record_error, &ti, "Record Error");

    proto_tree_add_item(subtree, hf_kafka_batch_index, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;

    offset = dissect_kafka_string(subtree, hf_kafka_batch_index_error_message, tvb, pinfo, offset, api_version >= 9, NULL, NULL);

    if (api_version >= 9) {
        offset = dissect_kafka_tagged_fields(tvb, pinfo, subtree, offset, 0);
    }

    proto_item_set_end(ti, tvb, offset);

    return offset;

}
static int
dissect_kafka_produce_response_partition(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset,
                                         kafka_api_version_t api_version) {
    proto_item *ti, *subti;
    proto_tree *subtree, *subsubtree;
    kafka_packet_values_t packet_values;
    memset(&packet_values, 0, sizeof(packet_values));

    subtree = proto_tree_add_subtree(tree, tvb, offset, -1, ett_kafka_partition, &ti, "Partition");

    offset = dissect_kafka_partition_id_ret(tvb, pinfo, subtree, offset, &packet_values.partition_id);

    offset = dissect_kafka_error(tvb, pinfo, subtree, offset);

    offset = dissect_kafka_offset_ret(tvb, pinfo, subtree, offset, &packet_values.offset);

    if (api_version >= 2) {
        offset = dissect_kafka_offset_time(tvb, pinfo, subtree, offset, api_version);
    }

    if (api_version >= 5) {
        proto_tree_add_item(subtree, hf_kafka_log_start_offset, tvb, offset, 8, ENC_BIG_ENDIAN);
        offset += 8;
    }

    if (api_version >= 8) {
        subsubtree = proto_tree_add_subtree(subtree, tvb, offset, -1, ett_kafka_record_errors, &subti, "Record Errors");
        offset = dissect_kafka_array(subsubtree, tvb, pinfo, offset, api_version >= 9, api_version,
                                     &dissect_kafka_produce_response_partition_record_error, NULL);
        proto_item_set_end(subti, tvb, offset);
    }

    if (api_version >= 8) {
        offset = dissect_kafka_string(subtree, hf_kafka_error_message, tvb, pinfo, offset, api_version >= 9, NULL, NULL);
    }

    if (api_version >= 9) {
        offset = dissect_kafka_tagged_fields(tvb, pinfo, subtree, offset, 0);
    }

    proto_item_set_end(ti, tvb, offset);

    proto_item_append_text(ti, " (ID=%u, Offset=%" PRIi64 ")",
                           packet_values.partition_id, packet_values.offset);

    return offset;
}

static int
dissect_kafka_produce_response_topic(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset,
                                     kafka_api_version_t api_version)
{
    proto_item *subti, *subsubti;
    proto_tree *subtree, *subsubtree;

    subtree = proto_tree_add_subtree(tree, tvb, offset, -1, ett_kafka_topic, &subti, "Topic");

    /* name */
    offset = dissect_kafka_string(subtree, hf_kafka_topic_name, tvb, pinfo, offset, api_version >= 9, NULL, NULL);

    /* [partitions] */
    subsubtree = proto_tree_add_subtree(subtree, tvb, offset, -1, ett_kafka_topic, &subsubti, "Partitions");
    offset = dissect_kafka_array(subsubtree, tvb, pinfo, offset, api_version >= 9, api_version,
                                 &dissect_kafka_produce_response_partition, NULL);
    proto_item_set_end(subsubti, tvb, offset);

    if (api_version >= 9) {
        offset = dissect_kafka_tagged_fields(tvb, pinfo, subtree, offset, 0);
    }

    proto_item_set_end(subti, tvb, offset);

    return offset;
}

static int
dissect_kafka_produce_response(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset,
                               kafka_api_version_t api_version)
{
    offset = dissect_kafka_array(tree, tvb, pinfo, offset, api_version >= 9, api_version, &dissect_kafka_produce_response_topic, NULL);

    if (api_version >= 1) {
        offset = dissect_kafka_throttle_time(tvb, pinfo, tree, offset);
    }

    if (api_version >= 9) {
        offset = dissect_kafka_tagged_fields(tvb, pinfo, tree, offset, 0);
    }

    return offset;
}

/* OFFSETS REQUEST/RESPONSE */

static int
dissect_kafka_offsets_request_partition(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                                        int offset, kafka_api_version_t api_version)
{
    proto_item *ti;
    proto_tree *subtree;
    kafka_partition_t partition = 0;

    subtree = proto_tree_add_subtree(tree, tvb, offset, -1, ett_kafka_partition, &ti, "Partition");

    offset = dissect_kafka_partition_id_ret(tvb, pinfo, subtree, offset, &partition);

    if (api_version >= 4) {
        proto_tree_add_item(subtree, hf_kafka_leader_epoch, tvb, offset, 4, ENC_BIG_ENDIAN);
        offset += 4;
    }

    offset = dissect_kafka_offset_time(tvb, pinfo, subtree, offset, api_version);

    if (api_version == 0) {
        proto_tree_add_item(subtree, hf_kafka_max_offsets, tvb, offset, 4, ENC_BIG_ENDIAN);
        offset += 4;
    }

    if (api_version >= 6) {
        offset = dissect_kafka_tagged_fields(tvb, pinfo, subtree, offset, 0);
    }

    proto_item_set_end(ti, tvb, offset);
    proto_item_append_text(ti, " (ID=%u)", partition);

    return offset;
}

static int
dissect_kafka_offsets_request_topic(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset,
                                    kafka_api_version_t api_version)
{
    proto_item *ti;
    proto_tree *subtree;

    subtree = proto_tree_add_subtree(tree, tvb, offset, -1, ett_kafka_topic, &ti, "Topic");

    offset = dissect_kafka_string(subtree, hf_kafka_topic_name, tvb, pinfo, offset, api_version >= 6, NULL, NULL);
    offset = dissect_kafka_array(subtree, tvb, pinfo, offset, api_version >= 6, api_version,
                                 &dissect_kafka_offsets_request_partition, NULL);

    if (api_version >= 6) {
        offset = dissect_kafka_tagged_fields(tvb, pinfo, subtree, offset, 0);
    }

    proto_item_set_end(ti, tvb, offset);

    return offset;
}

static int
dissect_kafka_offsets_request(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset,
                              kafka_api_version_t api_version)
{
    proto_item *subti;
    proto_tree *subtree;

    proto_tree_add_item(tree, hf_kafka_replica, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;

    if (api_version >= 2) {
        proto_tree_add_item(tree, hf_kafka_isolation_level, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset += 1;
    }

    subtree = proto_tree_add_subtree(tree, tvb, offset, -1, ett_kafka_broker, &subti, "Topics");

    offset = dissect_kafka_array(subtree, tvb, pinfo, offset, api_version >= 6, api_version,
                                 &dissect_kafka_offsets_request_topic, NULL);

    proto_item_set_end(subti, tvb, offset);

    if (api_version >= 6) {
        offset = dissect_kafka_tagged_fields(tvb, pinfo, tree, offset, 0);
    }

    return offset;
}

static int
dissect_kafka_offsets_response_partition(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                                         int offset, kafka_api_version_t api_version)
{
    proto_item *ti;
    proto_tree *subtree;
    kafka_partition_t partition = 0;

    subtree = proto_tree_add_subtree(tree, tvb, offset, -1, ett_kafka_partition, &ti, "Partition");

    offset = dissect_kafka_partition_id_ret(tvb, pinfo, subtree, offset, &partition);

    offset = dissect_kafka_error(tvb, pinfo, subtree, offset);

    if (api_version == 0) {
        offset = dissect_kafka_array(subtree, tvb, pinfo, offset, api_version >= 6, api_version, &dissect_kafka_offset, NULL);
    }
    else if (api_version >= 1) {
        offset = dissect_kafka_offset_time(tvb, pinfo, subtree, offset, api_version);

        offset = dissect_kafka_offset_ret(tvb, pinfo, subtree, offset, NULL);
    }

    if (api_version >= 4) {
        proto_tree_add_item(subtree, hf_kafka_leader_epoch, tvb, offset, 4, ENC_BIG_ENDIAN);
        offset += 4;
    }

    if (api_version >= 6) {
        offset = dissect_kafka_tagged_fields(tvb, pinfo, subtree, offset, 0);
    }

    proto_item_set_end(ti, tvb, offset);
    proto_item_append_text(ti, " (ID=%u)", partition);

    return offset;
}

static int
dissect_kafka_offsets_response_topic(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset,
                                     kafka_api_version_t api_version)
{
    proto_item *ti;
    proto_tree *subtree;

    subtree = proto_tree_add_subtree(tree, tvb, offset, -1, ett_kafka_topic, &ti, "Topic");

    offset = dissect_kafka_string(subtree, hf_kafka_topic_name, tvb, pinfo, offset, api_version >= 6, NULL, NULL);
    offset = dissect_kafka_array(subtree, tvb, pinfo, offset, api_version >= 6, api_version,
                                 &dissect_kafka_offsets_response_partition, NULL);

    if (api_version >= 6) {
        offset = dissect_kafka_tagged_fields(tvb, pinfo, subtree, offset, 0);
    }

    proto_item_set_end(ti, tvb, offset);

    return offset;
}

static int
dissect_kafka_offsets_response(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int start_offset,
                               kafka_api_version_t api_version)
{
    proto_item *subti;
    proto_tree *subtree;
    int offset = start_offset;

    if (api_version >= 2) {
        offset = dissect_kafka_throttle_time(tvb, pinfo, tree, offset);
    }

    subtree = proto_tree_add_subtree(tree, tvb, offset, -1, ett_kafka_broker, &subti, "Topics");

    offset = dissect_kafka_array(subtree, tvb, pinfo, offset, api_version >= 6, api_version,
                                 &dissect_kafka_offsets_response_topic, NULL);

    proto_item_set_end(subti, tvb, offset);

    if (api_version >= 6) {
        offset = dissect_kafka_tagged_fields(tvb, pinfo, tree, offset, 0);
    }

    return offset;
}

/* API_VERSIONS REQUEST/RESPONSE */

static int
dissect_kafka_api_versions_request(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                                   int offset, kafka_api_version_t api_version)
{
    if (api_version >= 3) {
        offset = dissect_kafka_compact_string(tree, hf_kafka_client_software_name, tvb, pinfo, offset, NULL, NULL);
        offset = dissect_kafka_compact_string(tree, hf_kafka_client_software_version, tvb, pinfo, offset, NULL, NULL);
        offset = dissect_kafka_tagged_fields(tvb, pinfo, tree, offset, 0);
    }

    return offset;
}

static int
dissect_kafka_api_versions_response_api_version(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree,
                                                int offset, kafka_api_version_t api_version _U_)
{
    proto_item *ti;
    proto_tree *subtree;
    kafka_api_key_t api_key;
    kafka_api_version_t min_version, max_version;
    const kafka_api_info_t *api_info;

    subtree = proto_tree_add_subtree(tree, tvb, offset, -1, ett_kafka_api_version, &ti,
                                     "API Version");

    api_key = tvb_get_ntohs(tvb, offset);
    proto_tree_add_item(subtree, hf_kafka_api_versions_api_key, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    min_version = tvb_get_ntohs(tvb, offset);
    proto_tree_add_item(subtree, hf_kafka_api_versions_min_version, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    max_version = tvb_get_ntohs(tvb, offset);
    proto_tree_add_item(subtree, hf_kafka_api_versions_max_version, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    proto_item_set_end(ti, tvb, offset);
    if (max_version != min_version) {
        /* Range of versions supported. */
        proto_item_append_text(subtree, " %s (v%d-%d)",
                               kafka_api_key_to_str(api_key),
                               min_version, max_version);
    }
    else {
        /* Only one version. */
        proto_item_append_text(subtree, " %s (v%d)",
                               kafka_api_key_to_str(api_key),
                               min_version);
    }

    api_info = kafka_get_api_info(api_key);
    if (api_info == NULL) {
        proto_item_append_text(subtree, " [Unknown API key]");
        expert_add_info_format(pinfo, ti, &ei_kafka_unknown_api_key,
                               "%s API key", kafka_api_key_to_str(api_key));
    }
    else if (!kafka_is_api_version_supported(api_info, min_version) ||
             !kafka_is_api_version_supported(api_info, max_version)) {
        if (api_info->min_version == -1) {
            proto_item_append_text(subtree, " [Unsupported API version]");
            expert_add_info_format(pinfo, ti, &ei_kafka_unsupported_api_version,
                                   "Unsupported %s version.",
                                   kafka_api_key_to_str(api_key));
        }
        else if (api_info->min_version == api_info->max_version) {
            proto_item_append_text(subtree, " [Unsupported API version. Supports v%d]",
                                   api_info->min_version);
            expert_add_info_format(pinfo, ti, &ei_kafka_unsupported_api_version,
                                   "Unsupported %s version. Supports v%d.",
                                   kafka_api_key_to_str(api_key), api_info->min_version);
        } else {
            proto_item_append_text(subtree, " [Unsupported API version. Supports v%d-%d]",
                                   api_info->min_version, api_info->max_version);
            expert_add_info_format(pinfo, ti, &ei_kafka_unsupported_api_version,
                                   "Unsupported %s version. Supports v%d-%d.",
                                   kafka_api_key_to_str(api_key),
                                   api_info->min_version, api_info->max_version);
        }
    }

    if (api_version >= 3) {
        offset = dissect_kafka_tagged_fields(tvb, pinfo, subtree, offset, 0);
    }

    return offset;
}

static int
dissect_kafka_api_versions_response(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset,
                                    kafka_api_version_t api_version)
{
    /* error_code */
    offset = dissect_kafka_error(tvb, pinfo, tree, offset);

    /* [api_version] */
    offset = dissect_kafka_array(tree, tvb, pinfo, offset, api_version >= 3, api_version,
                                 &dissect_kafka_api_versions_response_api_version, NULL);

    if (api_version >= 1) {
        offset = dissect_kafka_throttle_time(tvb, pinfo, tree, offset);
    }

    if (api_version >= 3) {
        offset = dissect_kafka_tagged_fields(tvb, pinfo, tree, offset, 0);
    }

    return offset;
}

/* UPDATE_METADATA REQUEST/RESPONSE */

static int
dissect_kafka_update_metadata_request_replica(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                                              int offset, kafka_api_version_t api_version _U_)
{
    return dissect_kafka_int32(tree, hf_kafka_replica, tvb, pinfo, offset, NULL);
}

static int
dissect_kafka_update_metadata_request_partition(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                                                      int offset, kafka_api_version_t api_version)
{
    proto_tree *subtree, *subsubtree;
    proto_item *subti, *subsubti;
    int topic_start, topic_len;
    kafka_partition_t partition;

    subtree = proto_tree_add_subtree(tree, tvb, offset, -1,
                                     ett_kafka_partition,
                                     &subti, "Partition");

    /* topic */
    if (api_version < 5) {
        offset = dissect_kafka_string(subtree, hf_kafka_topic_name, tvb, pinfo, offset, 0,
                                      &topic_start, &topic_len);
    }

    /* partition */
    offset = dissect_kafka_int32(subtree, hf_kafka_partition_id, tvb, pinfo, offset, &partition);

    /* controller_epoch */
    offset = dissect_kafka_int32(subtree, hf_kafka_controller_epoch, tvb, pinfo, offset, NULL);

    /* leader */
    offset = dissect_kafka_int32(subtree, hf_kafka_leader_id, tvb, pinfo, offset, NULL);

    /* leader_epoch */
    offset = dissect_kafka_int32(subtree, hf_kafka_leader_epoch, tvb, pinfo, offset, NULL);

    /* [isr] */
    subsubtree = proto_tree_add_subtree(subtree, tvb, offset, -1,
                                        ett_kafka_isrs,
                                        &subsubti, "Insync Replicas");
    offset = dissect_kafka_array(subsubtree, tvb, pinfo, offset, api_version >= 6, api_version,
                                 &dissect_kafka_update_metadata_request_replica, NULL);
    proto_item_set_end(subsubti, tvb, offset);

    /* zk_version */
    offset = dissect_kafka_int32(subtree, hf_kafka_zk_version, tvb, pinfo, offset, NULL);

    /* [replica] */
    subsubtree = proto_tree_add_subtree(subtree, tvb, offset, -1,
                                        ett_kafka_replicas,
                                        &subsubti, "Replicas");
    offset = dissect_kafka_array(subsubtree, tvb, pinfo, offset, api_version >= 6, api_version,
                                 &dissect_kafka_update_metadata_request_replica, NULL);
    proto_item_set_end(subsubti, tvb, offset);

    /* [offline_replica] */
    subsubtree = proto_tree_add_subtree(subtree, tvb, offset, -1,
                                        ett_kafka_replicas,
                                        &subsubti, "Offline Replicas");
    offset = dissect_kafka_array(subsubtree, tvb, pinfo, offset, api_version >= 6, api_version,
                                 &dissect_kafka_update_metadata_request_replica, NULL);
    proto_item_set_end(subsubti, tvb, offset);

    if (api_version >= 6) {
        offset = dissect_kafka_tagged_fields(tvb, pinfo, subtree, offset, 0);
    }

    proto_item_set_end(subti, tvb, offset);

    if (api_version >= 5) {
        proto_item_append_text(subti, " (Partition-ID=%u)",
                               partition);
    } else {
        proto_item_append_text(subti, " (Topic=%s, Partition-ID=%u)",
                               tvb_get_string_enc(pinfo->pool, tvb,
                                                  topic_start, topic_len, ENC_UTF_8),
                               partition);
    }
    return offset;
}

static int
dissect_kafka_update_metadata_request_topic(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                                            int offset, kafka_api_version_t api_version)
{
    proto_tree *subtree;
    proto_item *subti;
    int topic_start, topic_len;

    subtree = proto_tree_add_subtree(tree, tvb, offset, -1,
                                     ett_kafka_topic,
                                     &subti, "Topic");
    /* topic */
    offset = dissect_kafka_string(subtree, hf_kafka_topic_name, tvb, pinfo, offset, api_version >= 6,
                                  &topic_start, &topic_len);

    /* topic_id */
    if (api_version >= 7) {
        offset = dissect_kafka_uuid(subtree, hf_kafka_topic_id, tvb, pinfo, offset);
    }

    /* partitions */
    offset = dissect_kafka_array(subtree, tvb, pinfo, offset, api_version >= 6, api_version,
                                 &dissect_kafka_update_metadata_request_partition, NULL);

    if (api_version >= 6) {
        offset = dissect_kafka_tagged_fields(tvb, pinfo, subtree, offset, 0);
    }

    proto_item_set_end(subti, tvb, offset);
    proto_item_append_text(subti, " (Topic=%s)",
                           tvb_get_string_enc(pinfo->pool, tvb,
                                    topic_start, topic_len, ENC_UTF_8));

    return offset;
}

static int
dissect_kafka_update_metadata_request_endpoint(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                                                int offset, kafka_api_version_t api_version _U_)
{
    proto_item *subti;
    proto_tree *subtree;
    int host_start, host_len;
    int32_t broker_port;
    int16_t security_protocol_type;

    subtree = proto_tree_add_subtree(tree, tvb, offset, -1, ett_kafka_broker_end_point,
                                     &subti, "End Point");

    /* port */
    offset = dissect_kafka_int32(subtree, hf_kafka_broker_port, tvb, pinfo, offset, &broker_port);

    /* host */
    offset = dissect_kafka_string(subtree, hf_kafka_broker_host, tvb, pinfo, offset, api_version >= 6, &host_start, &host_len);

    /* listener_name */
    if (api_version >= 3) {
        offset = dissect_kafka_string(subtree, hf_kafka_listener_name, tvb, pinfo, offset, api_version >= 6, NULL, NULL);
    }

    /* security_protocol_type */
    offset = dissect_kafka_int16(subtree, hf_kafka_broker_security_protocol_type, tvb, pinfo, offset, &security_protocol_type);

    if (api_version >= 6) {
        offset = dissect_kafka_tagged_fields(tvb, pinfo, subtree, offset, 0);
    }

    proto_item_set_end(subti, tvb, offset);
    proto_item_append_text(subti, " (%s://%s:%d)",
                           val_to_str_const(security_protocol_type,
                                            kafka_security_protocol_types, "UNKNOWN"),
                           tvb_get_string_enc(pinfo->pool, tvb, host_start, host_len,
                                              ENC_UTF_8),
                           broker_port);

    return offset;
}

static int
dissect_kafka_update_metadata_request_broker(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                                                  int offset, kafka_api_version_t api_version)
{
    proto_item *subti;
    proto_tree *subtree;
    int32_t nodeid;

    subtree = proto_tree_add_subtree(tree, tvb, offset, -1, ett_kafka_broker,
                                     &subti, "Live Leader");

    /* id */
    offset = dissect_kafka_int32(subtree, hf_kafka_broker_nodeid, tvb, pinfo, offset, &nodeid);

    if (api_version == 0) {
        int host_start, host_len;
        int32_t broker_port;

        /* host */
        offset = dissect_kafka_string(subtree, hf_kafka_broker_host, tvb, pinfo, offset, 0, &host_start, &host_len);

        /* port */
        offset = dissect_kafka_int32(tree, hf_kafka_broker_port, tvb, pinfo, offset, &broker_port);

        proto_item_append_text(subti, " (node %u: %s:%u)",
                               nodeid,
                               tvb_get_string_enc(pinfo->pool, tvb, host_start, host_len,
                                                  ENC_UTF_8),
                               broker_port);
    } else if (api_version >= 1) {
        /* [end_point] */
        offset = dissect_kafka_array(subtree, tvb, pinfo, offset, api_version >= 6, api_version,
                                     &dissect_kafka_update_metadata_request_endpoint, NULL);

        if (api_version >= 2) {
            /* rack */
            offset = dissect_kafka_string(subtree, hf_kafka_rack, tvb, pinfo, offset, api_version >= 6, NULL, NULL);
        }

        proto_item_append_text(subti, " (node %d)",
                               nodeid);
    }

    if (api_version >= 6) {
        offset = dissect_kafka_tagged_fields(tvb, pinfo, subtree, offset, 0);
    }

    proto_item_set_end(subti, tvb, offset);

    return offset;
}

static int
dissect_kafka_update_metadata_request(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset,
                                      kafka_api_version_t api_version)
{
    int32_t controller_id;

    /* controller_id */
    offset = dissect_kafka_int32(tree, hf_kafka_controller_id, tvb, pinfo, offset, &controller_id);

    /* is_kraft_controller */
    if (api_version >= 8) {
        offset = dissect_kafka_bool(tree, hf_kafka_is_kraft_controller, tvb, pinfo, offset);
    }

    /* controller_epoch */
    offset = dissect_kafka_int32(tree, hf_kafka_controller_epoch, tvb, pinfo, offset, NULL);

    /* broker_epoch */
    if (api_version >= 5) {
        offset = dissect_kafka_int64(tree, hf_kafka_broker_epoch, tvb, pinfo, offset, NULL);
    }

    if (api_version >= 5) {
        /* [topic_state] */
        offset = dissect_kafka_array(tree, tvb, pinfo, offset, api_version >= 6, api_version,
                                     &dissect_kafka_update_metadata_request_topic, NULL);
    } else {
        /* [partition_state] */
        offset = dissect_kafka_array(tree, tvb, pinfo, offset, api_version >= 6, api_version,
                                     &dissect_kafka_update_metadata_request_partition, NULL);
    }

    /* [live_leader] */
    offset = dissect_kafka_array(tree, tvb, pinfo, offset, api_version >= 6, api_version,
                                 &dissect_kafka_update_metadata_request_broker, NULL);

    if (api_version >= 6) {
        offset = dissect_kafka_tagged_fields(tvb, pinfo, tree, offset, 0);
    }

    return offset;
}

static int
dissect_kafka_update_metadata_response(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset,
                                       kafka_api_version_t api_version)
{
    /* error_code */
    offset = dissect_kafka_error(tvb, pinfo, tree, offset);

    if (api_version >= 6) {
        offset = dissect_kafka_tagged_fields(tvb, pinfo, tree, offset, 0);
    }

    return offset;
}

/* CONTROLLED_SHUTDOWN REQUEST/RESPONSE */

static int
dissect_kafka_controlled_shutdown_request(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset,
                                          kafka_api_version_t api_version _U_)
{
    int32_t broker_id;

    /* broker_id */
    broker_id = (int32_t) tvb_get_ntohl(tvb, offset);
    proto_tree_add_item(tree, hf_kafka_broker_nodeid, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;

    if (api_version >= 2) {
        proto_tree_add_item(tree, hf_kafka_broker_epoch, tvb, offset, 8, ENC_BIG_ENDIAN);
        offset += 8;
    }

    if (api_version >= 3) {
        offset = dissect_kafka_tagged_fields(tvb, pinfo, tree, offset, 0);
    }

    col_append_fstr(pinfo->cinfo, COL_INFO, " (Broker-ID=%d)", broker_id);

    return offset;
}

static int
dissect_kafka_controlled_shutdown_response_partition_remaining(tvbuff_t *tvb, packet_info *pinfo,
                                                               proto_tree *tree, int offset,
                                                               kafka_api_version_t api_version)
{
    proto_item *subti;
    proto_tree *subtree;
    int topic_start, topic_len;
    kafka_partition_t partition;

    subtree = proto_tree_add_subtree(tree, tvb, offset, -1, ett_kafka_partition, &subti,
                                     "Partition Remaining");

    /* topic */
    offset = dissect_kafka_string(subtree, hf_kafka_topic_name, tvb, pinfo, offset, api_version >= 3,
                                  &topic_start, &topic_len);

    /* partition */
    partition = (int32_t) tvb_get_ntohl(tvb, offset);
    proto_tree_add_item(subtree, hf_kafka_partition_id, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;

    if (api_version >= 3) {
        offset = dissect_kafka_tagged_fields(tvb, pinfo, subtree, offset, 0);
    }

    proto_item_set_end(subti, tvb, offset);
    proto_item_append_text(subti, " (Topic=%s, Partition-ID=%d)",
                           tvb_get_string_enc(pinfo->pool, tvb,
                                              topic_start, topic_len, ENC_UTF_8),
                           partition);

    return offset;
}

static int
dissect_kafka_controlled_shutdown_response(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset,
                                           kafka_api_version_t api_version)
{
    /* error_code */
    offset = dissect_kafka_error(tvb, pinfo, tree, offset);

    /* [partition_remaining] */
    offset = dissect_kafka_array(tree, tvb, pinfo, offset, api_version >= 3, api_version,
                                 &dissect_kafka_controlled_shutdown_response_partition_remaining, NULL);

    if (api_version >= 3) {
        offset = dissect_kafka_tagged_fields(tvb, pinfo, tree, offset, 0);
    }

    return offset;
}

/* OFFSET_COMMIT REQUEST/RESPONSE */

static int
dissect_kafka_offset_commit_request_partition(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                                              int offset, kafka_api_version_t api_version _U_)
{
    proto_item *subti;
    proto_tree *subtree;
    kafka_partition_t partition_id;
    kafka_offset_t partition_offset;

    subtree = proto_tree_add_subtree(tree, tvb, offset, -1, ett_kafka_partition, &subti,
                                     "Partition");

    /* partition */
    partition_id = (int32_t) tvb_get_ntohl(tvb, offset);
    proto_tree_add_item(subtree, hf_kafka_partition_id, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;

    /* offset */
    partition_offset = (int64_t) tvb_get_ntoh64(tvb, offset);
    proto_tree_add_item(subtree, hf_kafka_offset, tvb, offset, 8, ENC_BIG_ENDIAN);
    offset += 8;

    if (api_version >= 6) {
        proto_tree_add_item(subtree, hf_kafka_leader_epoch, tvb, offset, 4, ENC_BIG_ENDIAN);
        offset += 4;
    }

    if (api_version == 1) {
        /* timestamp */
        proto_tree_add_item(subtree, hf_kafka_commit_timestamp, tvb, offset, 8, ENC_TIME_MSECS|ENC_BIG_ENDIAN);
        offset += 8;
    }

    /* metadata */
    offset = dissect_kafka_string(subtree, hf_kafka_metadata, tvb, pinfo, offset, api_version >= 8, NULL, NULL);

    if (api_version >= 8) {
        offset = dissect_kafka_tagged_fields(tvb, pinfo, subtree, offset, 0);
    }

    proto_item_set_end(subti, tvb, offset);
    proto_item_append_text(subti, " (ID=%u, Offset=%" PRIi64 ")",
                           partition_id, partition_offset);

    return offset;
}

static int
dissect_kafka_offset_commit_request_topic(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                                          int offset, kafka_api_version_t api_version)
{
    proto_item *subti;
    proto_tree *subtree;
    int topic_start, topic_len;

    subtree = proto_tree_add_subtree(tree, tvb, offset, -1, ett_kafka_topic, &subti, "Topic");

    /* topic */
    offset = dissect_kafka_string(subtree, hf_kafka_topic_name, tvb, pinfo, offset, api_version >= 8,
                                  &topic_start, &topic_len);
    /* [partition] */
    offset = dissect_kafka_array(subtree, tvb, pinfo, offset, api_version >= 8, api_version,
                                 &dissect_kafka_offset_commit_request_partition, NULL);

    if (api_version >= 8) {
        offset = dissect_kafka_tagged_fields(tvb, pinfo, subtree, offset, 0);
    }

    proto_item_set_end(subti, tvb, offset);
    proto_item_append_text(subti, " (Topic=%s)",
                           tvb_get_string_enc(pinfo->pool, tvb,
                                              topic_start, topic_len, ENC_UTF_8));

    return offset;
}

static int
dissect_kafka_offset_commit_request(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset,
                                    kafka_api_version_t api_version)
{
    int group_start = 0, group_len;

    /* group_id */
    offset = dissect_kafka_string(tree, hf_kafka_consumer_group, tvb, pinfo, offset, api_version >= 8,
                                  &group_start, &group_len);

    if (api_version >= 1) {
        /* group_generation_id */
        proto_tree_add_item(tree, hf_kafka_generation_id, tvb, offset, 4, ENC_BIG_ENDIAN);
        offset += 4;
    }

    /* member_id */
    if (api_version >= 1) {
        offset = dissect_kafka_string(tree, hf_kafka_member_id, tvb, pinfo, offset, api_version >= 8, NULL, NULL);
    }

    /* instance_id */
    if (api_version >= 7) {
        offset = dissect_kafka_string(tree, hf_kafka_consumer_group_instance, tvb, pinfo, offset, api_version >= 8, NULL, NULL);
    }

    /* retention_time */
    if (api_version >= 2 && api_version < 5) {
        proto_tree_add_item(tree, hf_kafka_retention_time, tvb, offset, 8, ENC_BIG_ENDIAN);
        offset += 8;
    }

    /* [topic] */
    offset = dissect_kafka_array(tree, tvb, pinfo, offset, api_version >= 8, api_version,
                                 &dissect_kafka_offset_commit_request_topic, NULL);

    if (api_version >= 8) {
        offset = dissect_kafka_tagged_fields(tvb, pinfo, tree, offset, 0);
    }

    col_append_fstr(pinfo->cinfo, COL_INFO,
                    " (Group=%s)",
                    tvb_get_string_enc(pinfo->pool, tvb,
                                       group_start, group_len, ENC_UTF_8));

    return offset;
}

static int
dissect_kafka_offset_commit_response_partition_response(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                                                        int offset, kafka_api_version_t api_version _U_)
{
    proto_item *subti;
    proto_tree *subtree;
    kafka_partition_t partition;
    kafka_error_t error;

    subtree = proto_tree_add_subtree(tree, tvb, offset, -1, ett_kafka_partition, &subti,
                                     "Partition");

    /* partition */
    partition = (int32_t) tvb_get_ntohl(tvb, offset);
    proto_tree_add_item(subtree, hf_kafka_partition_id, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;

    /* error_code */
    offset = dissect_kafka_error_ret(tvb, pinfo, subtree, offset, &error);

    if (api_version >= 8) {
        offset = dissect_kafka_tagged_fields(tvb, pinfo, subtree, offset, 0);
    }

    proto_item_set_end(subti, tvb, offset);
    proto_item_append_text(subti, " (Partition-ID=%d, Error=%s)",
                           partition, kafka_error_to_str(error));

    return offset;
}

static int
dissect_kafka_offset_commit_response_response(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                                              int offset, kafka_api_version_t api_version)
{
    proto_item *subti;
    proto_tree *subtree;
    int topic_start, topic_len;

    subtree = proto_tree_add_subtree(tree, tvb, offset, -1, ett_kafka_topic, &subti, "Topic");

    /* topic */
    offset = dissect_kafka_string(subtree, hf_kafka_topic_name, tvb, pinfo, offset, api_version >= 8,
                                  &topic_start, &topic_len);

    /* [partition_response] */
    offset = dissect_kafka_array(subtree, tvb, pinfo, offset, api_version >= 8, api_version,
                                 &dissect_kafka_offset_commit_response_partition_response, NULL);

    if (api_version >= 8) {
        offset = dissect_kafka_tagged_fields(tvb, pinfo, subtree, offset, 0);
    }

    proto_item_set_end(subti, tvb, offset);
    proto_item_append_text(subti, " (Name=%s)",
                           tvb_get_string_enc(pinfo->pool, tvb,
                                              topic_start, topic_len, ENC_UTF_8));

    return offset;
}

static int
dissect_kafka_offset_commit_response(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset,
                                     kafka_api_version_t api_version)
{
    if (api_version >= 3) {
        offset = dissect_kafka_throttle_time(tvb, pinfo, tree, offset);
    }

    /* [responses] */
    offset = dissect_kafka_array(tree, tvb, pinfo, offset, api_version >= 8, api_version,
                                 &dissect_kafka_offset_commit_response_response, NULL);

    if (api_version >= 8) {
        offset = dissect_kafka_tagged_fields(tvb, pinfo, tree, offset, 0);
    }

    return offset;
}

/* GROUP_COORDINATOR REQUEST/RESPONSE */

static int
dissect_kafka_find_coordinator_request_coordinator_keys(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset,
                                                        kafka_api_version_t api_version)
{
    if (api_version >= 4) {
        offset = dissect_kafka_string(tree, hf_kafka_coordinator_key, tvb, pinfo, offset, api_version >= 4, NULL, NULL);
    }

    return offset;
}

static int
dissect_kafka_find_coordinator_request(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset,
                                        kafka_api_version_t api_version _U_)
{
    proto_item *subti;
    proto_tree *subtree;
    int group_start, group_len;

    if (api_version == 0) {
        /* group_id */
        offset = dissect_kafka_string(tree, hf_kafka_consumer_group, tvb, pinfo, offset, 0,
                                      &group_start, &group_len);

        col_append_fstr(pinfo->cinfo, COL_INFO,
                        " (Group=%s)",
                        tvb_get_string_enc(pinfo->pool, tvb,
                                           group_start, group_len, ENC_UTF_8));
    }

    if (api_version >= 0 && api_version <= 3) {
        offset = dissect_kafka_string(tree, hf_kafka_coordinator_key, tvb, pinfo, offset, api_version >= 3,
                                      NULL, NULL);
    }

    if (api_version >= 1) {
        proto_tree_add_item(tree, hf_kafka_coordinator_type, tvb, offset, 1, ENC_NA);
        offset += 1;
    }

    if (api_version >= 4) {
        subtree = proto_tree_add_subtree(tree, tvb, offset, -1, ett_kafka_topic, &subti, "Coordinator Keys");

        offset = dissect_kafka_array(subtree, tvb, pinfo, offset, api_version >= 3, api_version,
                                     &dissect_kafka_find_coordinator_request_coordinator_keys, NULL);

        proto_item_set_end(subti, tvb, offset);
    }

    if (api_version >= 3) {
        offset = dissect_kafka_tagged_fields(tvb, pinfo, tree, offset, 0);
    }

    return offset;
}

static int
dissect_kafka_find_coordinator_response_coordinator_v1(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                                                       int offset, kafka_api_version_t api_version)
{
    proto_item *subti;
    proto_tree *subtree;
    int32_t node_id;
    int host_start, host_len;
    int32_t port;

    subtree = proto_tree_add_subtree(tree, tvb, offset, -1, ett_kafka_broker, &subti, "Coordinator");

    /* node_id */
    node_id = (int32_t) tvb_get_ntohl(tvb, offset);
    proto_tree_add_item(subtree, hf_kafka_broker_nodeid, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;

    /* host */
    offset = dissect_kafka_string(subtree, hf_kafka_broker_host, tvb, pinfo, offset, api_version >= 3,
                                  &host_start, &host_len);

     /* port */
    port = (int32_t) tvb_get_ntohl(tvb, offset);
    proto_tree_add_item(subtree, hf_kafka_broker_port, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;

    proto_item_set_end(subti, tvb, offset);

    if (node_id >= 0) {
        proto_item_append_text(subti, " (node %d: %s:%d)",
                               node_id,
                               tvb_get_string_enc(pinfo->pool, tvb,
                                                  host_start, host_len, ENC_UTF_8),
                               port);
    } else {
        proto_item_append_text(subti, " (none)");
    }

    return offset;
}

static int
dissect_kafka_find_coordinator_response_coordinator_v2(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                                                       int offset, kafka_api_version_t api_version)
{
    proto_item *subti;
    proto_tree *subtree;
    int32_t node_id;
    int host_start, host_len;
    int32_t port;

    subtree = proto_tree_add_subtree(tree, tvb, offset, -1, ett_kafka_broker, &subti, "Coordinator");

    /* key */
    offset = dissect_kafka_string(subtree, hf_kafka_coordinator_key, tvb, pinfo, offset, api_version >= 3, NULL, NULL);

    /* node_id */
    node_id = (int32_t) tvb_get_ntohl(tvb, offset);
    proto_tree_add_item(subtree, hf_kafka_broker_nodeid, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;

    /* host */
    offset = dissect_kafka_string(subtree, hf_kafka_broker_host, tvb, pinfo, offset, api_version >= 3,
                                  &host_start, &host_len);

    /* port */
    port = (int32_t) tvb_get_ntohl(tvb, offset);
    proto_tree_add_item(subtree, hf_kafka_broker_port, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;

    /* error_code */
    offset = dissect_kafka_error(tvb, pinfo, subtree, offset);

    /* error_message */
    offset = dissect_kafka_string(subtree, hf_kafka_error_message, tvb, pinfo, offset, api_version >= 3,
                                  NULL, NULL);

    offset = dissect_kafka_tagged_fields(tvb, pinfo, subtree, offset, 0);

    proto_item_set_end(subti, tvb, offset);

    if (node_id >= 0) {
        proto_item_append_text(subti, " (node %d: %s:%d)",
                               node_id,
                               tvb_get_string_enc(pinfo->pool, tvb,
                                                  host_start, host_len, ENC_UTF_8),
                               port);
    } else {
        proto_item_append_text(subti, " (none)");
    }

    return offset;
}

static int
dissect_kafka_find_coordinator_response(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset,
                                         kafka_api_version_t api_version)
{
    proto_item *subti;
    proto_tree *subtree;

    if (api_version >= 1) {
        offset = dissect_kafka_throttle_time(tvb, pinfo, tree, offset);
    }

    /* error_code */
    if (api_version >= 0 && api_version <= 3) {
        offset = dissect_kafka_error(tvb, pinfo, tree, offset);
    }

    /* error_message */
    if (api_version >= 1 && api_version <= 3) {
        offset = dissect_kafka_string(tree, hf_kafka_error_message, tvb, pinfo, offset, api_version >= 3,
                                      NULL, NULL);
    }

    /* In versions 0-3, coordinator fields exist once on the message (one single coordinator) in a flat layout.
     * In version 3+, this has been changed to an array of coordinators, each with some extra fields compared to the
     * original single coordinator. */
    if (api_version >= 0 && api_version <= 3) {
        /* coordinator */
        offset = dissect_kafka_find_coordinator_response_coordinator_v1(tvb, pinfo, tree, offset, api_version);
    }
    else if (api_version >= 4) {
        /* [coordinators] */
        subtree = proto_tree_add_subtree(tree, tvb, offset, -1, ett_kafka_broker, &subti, "Coordinators");

        offset = dissect_kafka_array(subtree, tvb, pinfo, offset, api_version >= 3, api_version,
                                     &dissect_kafka_find_coordinator_response_coordinator_v2, NULL);

        proto_item_set_end(subti, tvb, offset);
    }

    if (api_version >= 3) {
        offset = dissect_kafka_tagged_fields(tvb, pinfo, tree, offset, 0);
    }

    return offset;
}

/* JOIN_GROUP REQUEST/RESPONSE */

static int
dissect_kafka_join_group_request_group_protocols(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                                                 int offset, kafka_api_version_t api_version _U_)
{
    proto_item *subti;
    proto_tree *subtree;
    int protocol_start, protocol_len;

    subtree = proto_tree_add_subtree(tree, tvb, offset, -1, ett_kafka_group_protocol, &subti,
                                     "Group Protocol");

    /* protocol_name */
    offset = dissect_kafka_string(subtree, hf_kafka_protocol_name, tvb, pinfo, offset, api_version >= 6,
                                  &protocol_start, &protocol_len);

    /* protocol_metadata */
    offset = dissect_kafka_bytes(subtree, hf_kafka_protocol_metadata, tvb, pinfo, offset, api_version >= 6, NULL, NULL);

    if (api_version >= 6) {
        offset = dissect_kafka_tagged_fields(tvb, pinfo, subtree, offset, 0);
    }

    proto_item_set_end(subti, tvb, offset);
    proto_item_append_text(subti, " (Group-ID=%s)",
                           tvb_get_string_enc(pinfo->pool, tvb,
                                              protocol_start, protocol_len, ENC_UTF_8));

    return offset;
}

static int
dissect_kafka_join_group_request(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset,
                                 kafka_api_version_t api_version)
{
    proto_item *subti;
    proto_tree *subtree;
    int group_start, group_len;
    int member_start, member_len;

    /* group_id */
    offset = dissect_kafka_string(tree, hf_kafka_consumer_group, tvb, pinfo, offset, api_version >= 6,
                                  &group_start, &group_len);

    /* session_timeout */
    proto_tree_add_item(tree, hf_kafka_session_timeout, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;

    if (api_version > 0) {
        /* rebalance_timeout */
        proto_tree_add_item(tree, hf_kafka_rebalance_timeout, tvb, offset, 4, ENC_BIG_ENDIAN);
        offset += 4;
    }

    /* member_id */
    offset = dissect_kafka_string(tree, hf_kafka_member_id, tvb, pinfo, offset, api_version >= 6,
                                  &member_start, &member_len);

    /* instance id */
    if (api_version >= 5) {
        offset = dissect_kafka_string(tree, hf_kafka_consumer_group_instance, tvb, pinfo, offset, api_version >= 6,
                                      NULL, NULL);
    }

    /* protocol_type */
    offset = dissect_kafka_string(tree, hf_kafka_protocol_type, tvb, pinfo, offset, api_version >= 6, NULL, NULL);

    /* [group_protocols] */
    subtree = proto_tree_add_subtree(tree, tvb, offset, -1, ett_kafka_group_protocols, &subti,
                                     "Group Protocols");
    offset = dissect_kafka_array(subtree, tvb, pinfo, offset, api_version >= 6, api_version,
                                 &dissect_kafka_join_group_request_group_protocols, NULL);
    proto_item_set_end(subti, tvb, offset);

    /* join_reason */
    offset = dissect_kafka_string(tree, hf_kafka_join_reason, tvb, pinfo, offset, api_version >= 6, NULL, NULL);

    col_append_fstr(pinfo->cinfo, COL_INFO,
                    " (Group=%s, Member=%s)",
                    kafka_tvb_get_string(pinfo->pool, tvb, group_start, group_len),
                    kafka_tvb_get_string(pinfo->pool, tvb, member_start, member_len));

    if (api_version >= 6) {
        offset = dissect_kafka_tagged_fields(tvb, pinfo, tree, offset, 0);
    }

    return offset;
}

static int
dissect_kafka_join_group_response_member(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                                         int offset, kafka_api_version_t api_version)
{
    proto_item *subti;
    proto_tree *subtree;
    int member_start, member_len;

    subtree = proto_tree_add_subtree(tree, tvb, offset, -1, ett_kafka_group_member, &subti, "Member");

    /* member_id */
    offset = dissect_kafka_string(subtree, hf_kafka_member_id, tvb, pinfo, offset, api_version >= 6,
                                  &member_start, &member_len);

    /* instance id */
    if (api_version >= 5) {
        offset = dissect_kafka_string(subtree, hf_kafka_consumer_group_instance, tvb, pinfo, offset, api_version >= 6,
                                      NULL, NULL);
    }

    /* member_metadata */
    offset = dissect_kafka_bytes(subtree, hf_kafka_member_metadata, tvb, pinfo, offset, api_version >= 6, NULL, NULL);

    if (api_version >= 6) {
        offset = dissect_kafka_tagged_fields(tvb, pinfo, subtree, offset, 0);
    }

    proto_item_set_end(subti, tvb, offset);
    proto_item_append_text(subti, " (Member=%s)",
                           tvb_get_string_enc(pinfo->pool, tvb,
                                              member_start, member_len, ENC_UTF_8));

    return offset;
}

static int
dissect_kafka_join_group_response(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset,
                                  kafka_api_version_t api_version)
{
    proto_item *subti;
    proto_tree *subtree;
    int member_start = 0, member_len;

    if (api_version >= 2) {
        offset = dissect_kafka_throttle_time(tvb, pinfo, tree, offset);
    }

    /* error_code */
    offset = dissect_kafka_error(tvb, pinfo, tree, offset);

    /* generation_id */
    proto_tree_add_item(tree, hf_kafka_generation_id, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;

    /* group_protocol_type */
    if (api_version >= 7) {
        offset = dissect_kafka_string(tree, hf_kafka_protocol_type, tvb, pinfo, offset, 1,NULL, NULL);
    }

    /* group_protocol */
    offset = dissect_kafka_string(tree, hf_kafka_protocol_name, tvb, pinfo, offset, api_version >= 6, NULL, NULL);

    /* leader_id */
    offset = dissect_kafka_string(tree, hf_kafka_group_leader_id, tvb, pinfo, offset, api_version >= 6, NULL, NULL);

    /* skip_assignment */
    offset = dissect_kafka_bool(tree, hf_kafka_skip_assignment, tvb, pinfo, offset);

    /* member_id */
    offset = dissect_kafka_string(tree, hf_kafka_member_id, tvb, pinfo, offset, api_version >= 6, &member_start, &member_len);

    /* [member] */
    subtree = proto_tree_add_subtree(tree, tvb, offset, -1, ett_kafka_group_members, &subti, "Members");
    offset = dissect_kafka_array(subtree, tvb, pinfo, offset, api_version >= 6, api_version,
                                 &dissect_kafka_join_group_response_member, NULL);
    proto_item_set_end(subti, tvb, offset);

    col_append_fstr(pinfo->cinfo, COL_INFO,
                    " (Member=%s)",
                    tvb_get_string_enc(pinfo->pool, tvb,
                                       member_start, member_len, ENC_UTF_8));

    if (api_version >= 6) {
        offset = dissect_kafka_tagged_fields(tvb, pinfo, tree, offset, 0);
    }

    return offset;
}

/* HEARTBEAT REQUEST/RESPONSE */

static int
dissect_kafka_heartbeat_request(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset,
                                kafka_api_version_t api_version _U_)
{
    int group_start, group_len;
    int member_start, member_len;

    /* group_id */
    offset = dissect_kafka_string(tree, hf_kafka_consumer_group, tvb, pinfo, offset, api_version >= 4,
                                  &group_start, &group_len);

    /* group_generation_id */
    proto_tree_add_item(tree, hf_kafka_generation_id, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;

    /* member_id */
    offset = dissect_kafka_string(tree, hf_kafka_member_id, tvb, pinfo, offset, api_version >= 4,
                                  &member_start, &member_len);

    /* instance_id */
    if (api_version >= 3) {
        offset = dissect_kafka_string(tree, hf_kafka_consumer_group_instance, tvb, pinfo, offset, api_version >= 4,
                                      NULL, NULL);
    }

    col_append_fstr(pinfo->cinfo, COL_INFO,
                    " (Group=%s, Member=%s)",
                    tvb_get_string_enc(pinfo->pool, tvb,
                                       group_start, group_len, ENC_UTF_8),
                    tvb_get_string_enc(pinfo->pool, tvb,
                                       member_start, member_len, ENC_UTF_8));

    if (api_version >= 4) {
        offset = dissect_kafka_tagged_fields(tvb, pinfo, tree, offset, 0);
    }

    return offset;
}

static int
dissect_kafka_heartbeat_response(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset,
                                 kafka_api_version_t api_version _U_)
{
    if (api_version >= 1) {
        offset = dissect_kafka_throttle_time(tvb, pinfo, tree, offset);
    }

    /* error_code */
    offset = dissect_kafka_error(tvb, pinfo, tree, offset);

    if (api_version >= 4) {
        offset = dissect_kafka_tagged_fields(tvb, pinfo, tree, offset, 0);
    }

    return offset;
}

/* LEAVE_GROUP REQUEST/RESPONSE */

static int
dissect_kafka_leave_group_request_member(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset,
                                  kafka_api_version_t api_version)
{
    proto_item *subti;
    proto_tree *subtree;
    int member_start, member_len;
    int instance_start, instance_len;

    subtree = proto_tree_add_subtree(tree, tvb, offset, -1, ett_kafka_group_member, &subti, "Member");

    /* member_id */
    offset = dissect_kafka_string(subtree, hf_kafka_member_id, tvb, pinfo, offset, api_version >= 4,
                                  &member_start, &member_len);

    /* instance_id */
    offset = dissect_kafka_string(subtree, hf_kafka_consumer_group_instance, tvb, pinfo, offset, api_version >= 4,
                                  &instance_start, &instance_len);

    /* leave_reason */
    if (api_version >= 5) {
        offset = dissect_kafka_string(subtree, hf_kafka_leave_reason, tvb, pinfo, offset, api_version >= 4, NULL, NULL);
    }

    if (api_version >= 4) {
        offset = dissect_kafka_tagged_fields(tvb, pinfo, subtree, offset, 0);
    }

    proto_item_set_end(subti, tvb, offset);

    if (instance_len >= 0) {
        proto_item_append_text(subti, " (Member=%s, Group-Instance=%s)",
                               tvb_get_string_enc(pinfo->pool, tvb,
                                                  member_start, member_len, ENC_UTF_8),
                               tvb_get_string_enc(pinfo->pool, tvb,
                                                  instance_start, instance_len, ENC_UTF_8)
        );
    } else {
        proto_item_append_text(subti, " (Member=%s)",
                               tvb_get_string_enc(pinfo->pool, tvb,
                                                  member_start, member_len, ENC_UTF_8)
        );
    }

    return offset;
}

static int
dissect_kafka_leave_group_request(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset,
                                  kafka_api_version_t api_version)
{
    int group_start, group_len;
    int member_start, member_len;
    proto_item *subti;
    proto_tree *subtree;

    /* group_id */
    offset = dissect_kafka_string(tree, hf_kafka_consumer_group, tvb, pinfo, offset, api_version >= 4,
                                  &group_start, &group_len);

    if (api_version >= 0 && api_version <= 2) {

        /* member_id */
        offset = dissect_kafka_string(tree, hf_kafka_member_id, tvb, pinfo, offset, 0,
                                      &member_start, &member_len);

        col_append_fstr(pinfo->cinfo, COL_INFO,
                        " (Group=%s, Member=%s)",
                        tvb_get_string_enc(pinfo->pool, tvb,
                                           group_start, group_len, ENC_UTF_8),
                        tvb_get_string_enc(pinfo->pool, tvb,
                                           member_start, member_len, ENC_UTF_8));

    } else if (api_version >= 3) {

        // KIP-345
        subtree = proto_tree_add_subtree(tree, tvb, offset, -1, ett_kafka_group_members, &subti, "Members");
        offset = dissect_kafka_array(subtree, tvb, pinfo, offset, api_version >= 4, api_version,
                                     &dissect_kafka_leave_group_request_member, NULL);
        proto_item_set_end(subti, tvb, offset);

        col_append_fstr(pinfo->cinfo, COL_INFO,
                        " (Group=%s)",
                        tvb_get_string_enc(pinfo->pool, tvb,
                                           group_start, group_len, ENC_UTF_8));

    }

    if (api_version >= 4) {
        offset = dissect_kafka_tagged_fields(tvb, pinfo, tree, offset, 0);
    }

    return offset;
}

static int
dissect_kafka_leave_group_response_member(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset,
                                                  kafka_api_version_t api_version)
{
    proto_item *subti;
    proto_tree *subtree;
    int member_start, member_len;
    int instance_start, instance_len;

    subtree = proto_tree_add_subtree(tree, tvb, offset, -1, ett_kafka_group_member, &subti, "Member");

    /* member_id */
    offset = dissect_kafka_string(subtree, hf_kafka_member_id, tvb, pinfo, offset, api_version >= 4,
                                  &member_start, &member_len);

    /* instance_id */
    offset = dissect_kafka_string(subtree, hf_kafka_consumer_group_instance, tvb, pinfo, offset, api_version >= 4,
                                  &instance_start, &instance_len);

    /* error_code */
    offset = dissect_kafka_error(tvb, pinfo, subtree, offset);

    if (api_version >= 4) {
        offset = dissect_kafka_tagged_fields(tvb, pinfo, subtree, offset, 0);
    }

    proto_item_set_end(subti, tvb, offset);

    if (instance_len >= 0) {
        proto_item_append_text(subti, " (Member=%s, Group-Instance=%s)",
                               tvb_get_string_enc(pinfo->pool, tvb,
                                                  member_start, member_len, ENC_UTF_8),
                               tvb_get_string_enc(pinfo->pool, tvb,
                                                  instance_start, instance_len, ENC_UTF_8)
        );
    } else {
        proto_item_append_text(subti, " (Member=%s)",
                               tvb_get_string_enc(pinfo->pool, tvb,
                                                  member_start, member_len, ENC_UTF_8)
        );
    }

    return offset;
}

static int
dissect_kafka_leave_group_response(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset,
                                   kafka_api_version_t api_version _U_)
{
    proto_item *subti;
    proto_tree *subtree;

    if (api_version >= 1) {
        offset = dissect_kafka_throttle_time(tvb, pinfo, tree, offset);
    }

    /* error_code */
    offset = dissect_kafka_error(tvb, pinfo, tree, offset);

    if (api_version >= 3) {

        // KIP-345
        subtree = proto_tree_add_subtree(tree, tvb, offset, -1, ett_kafka_group_members, &subti, "Members");
        offset = dissect_kafka_array(subtree, tvb, pinfo, offset, api_version >= 4, api_version,
                                     &dissect_kafka_leave_group_response_member, NULL);
        proto_item_set_end(subti, tvb, offset);

    }

    if (api_version >= 4) {
        offset = dissect_kafka_tagged_fields(tvb, pinfo, tree, offset, 0);
    }

    return offset;
}

/* SYNC_GROUP REQUEST/RESPONSE */

static int
dissect_kafka_sync_group_request_group_assignment(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                                                  int offset, kafka_api_version_t api_version _U_)
{
    proto_item *subti;
    proto_tree *subtree;
    int member_start, member_len;

    subtree = proto_tree_add_subtree(tree, tvb, offset, -1, ett_kafka_group_assignment, &subti,
                                     "Group Assignment");

    /* member_id */
    offset = dissect_kafka_string(subtree, hf_kafka_member_id, tvb, pinfo, offset, api_version >= 4,
                                  &member_start, &member_len);

    /* member_assignment */
    offset = dissect_kafka_bytes(subtree, hf_kafka_member_assignment, tvb, pinfo, offset, api_version >= 4, NULL, NULL);

    if (api_version >= 4) {
        offset = dissect_kafka_tagged_fields(tvb, pinfo, subtree, offset, 0);
    }

    proto_item_set_end(subti, tvb, offset);
    proto_item_append_text(subti, " (Member=%s)",
                           tvb_get_string_enc(pinfo->pool, tvb,
                                              member_start, member_len, ENC_UTF_8));

    return offset;
}

static int
dissect_kafka_sync_group_request(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset,
                                 kafka_api_version_t api_version)
{
    proto_item *subti;
    proto_tree *subtree;
    int group_start, group_len;
    int member_start, member_len;

    /* group_id */
    offset = dissect_kafka_string(tree, hf_kafka_consumer_group, tvb, pinfo, offset, api_version >= 4,
                                  &group_start, &group_len);

    /* generation_id */
    proto_tree_add_item(tree, hf_kafka_generation_id, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;

    /* member_id */
    offset = dissect_kafka_string(tree, hf_kafka_member_id, tvb, pinfo, offset, api_version >= 4,
                                  &member_start, &member_len);

    /* instance_id */
    if (api_version >= 3) {
        offset = dissect_kafka_string(tree, hf_kafka_consumer_group_instance, tvb, pinfo, offset, api_version >= 4,
                                      NULL, NULL);
    }

    /* protocol_type */
    if (api_version >= 5) {
        offset = dissect_kafka_string(tree, hf_kafka_protocol_type, tvb, pinfo, offset, 1,
                                              NULL, NULL);
    }

    /* protocol_name */
    if (api_version >= 5) {
        offset = dissect_kafka_string(tree, hf_kafka_protocol_name, tvb, pinfo, offset, 1,
                                              NULL, NULL);
    }

    /* [group_assignment] */
    subtree = proto_tree_add_subtree(tree, tvb, offset, -1, ett_kafka_group_assignments, &subti,
                                     "Group Assignments");
    offset = dissect_kafka_array(subtree, tvb, pinfo, offset, api_version >= 4, api_version,
                                 &dissect_kafka_sync_group_request_group_assignment, NULL);

    if (api_version >= 4) {
        offset = dissect_kafka_tagged_fields(tvb, pinfo, tree, offset, 0);
    }

    proto_item_set_end(subti, tvb, offset);

    col_append_fstr(pinfo->cinfo, COL_INFO,
                    " (Group=%s, Member=%s)",
                    tvb_get_string_enc(pinfo->pool, tvb,
                                       group_start, group_len, ENC_UTF_8),
                    tvb_get_string_enc(pinfo->pool, tvb,
                                       member_start, member_len, ENC_UTF_8));

    return offset;
}

static int
dissect_kafka_sync_group_response(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset,
                                  kafka_api_version_t api_version _U_)
{
    if (api_version >= 1) {
        offset = dissect_kafka_throttle_time(tvb, pinfo, tree, offset);
    }

    /* error_code */
    offset = dissect_kafka_error(tvb, pinfo, tree, offset);

    /* protocol_type */
    if (api_version >= 5) {
        offset = dissect_kafka_compact_string(tree, hf_kafka_protocol_type, tvb, pinfo, offset,
                                              NULL, NULL);
    }

    /* protocol_name */
    if (api_version >= 5) {
        offset = dissect_kafka_compact_string(tree, hf_kafka_protocol_name, tvb, pinfo, offset,
                                              NULL, NULL);
    }

    /* member_assignment */
    offset = dissect_kafka_bytes(tree, hf_kafka_member_assignment, tvb, pinfo, offset, api_version >= 4, NULL, NULL);

    if (api_version >= 4) {
        offset = dissect_kafka_tagged_fields(tvb, pinfo, tree, offset, 0);
    }

    return offset;
}

/* DESCRIBE_GROUPS REQUEST/RESPONSE */

static int
dissect_kafka_describe_groups_request_group_id(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                                              int offset, kafka_api_version_t api_version _U_)
{
    /* group_id */
    offset = dissect_kafka_string(tree, hf_kafka_consumer_group, tvb, pinfo, offset, api_version >= 5, NULL, NULL);

    return offset;
}

static int
dissect_kafka_describe_groups_request(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset,
                                      kafka_api_version_t api_version)
{
    /* [group_id] */
    offset = dissect_kafka_array(tree, tvb, pinfo, offset, api_version >= 5, api_version,
                                 &dissect_kafka_describe_groups_request_group_id, NULL);

    if (api_version >= 3) {
        proto_tree_add_item(tree, hf_kafka_include_group_authorized_ops, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset += 1;
    }

    if (api_version >= 5) {
        offset = dissect_kafka_tagged_fields(tvb, pinfo, tree, offset, 0);
    }

    return offset;
}

static int
dissect_kafka_describe_groups_response_member(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset,
                                              kafka_api_version_t api_version _U_)
{
    proto_item *subti;
    proto_tree *subtree;
    int member_start, member_len = -1;
    int instance_start, instance_len = -1;

    subtree = proto_tree_add_subtree(tree, tvb, offset, -1, ett_kafka_group_member, &subti, "Member");

    /* member_id */
    offset = dissect_kafka_string(subtree, hf_kafka_member_id, tvb, pinfo, offset, api_version >= 5,
                                  &member_start, &member_len);

    /* instance_id */
    if (api_version >= 4) {
        offset = dissect_kafka_string(subtree, hf_kafka_consumer_group_instance, tvb, pinfo, offset, api_version >= 5,
                                      &instance_start, &instance_len);
    }

    /* client_id */
    offset = dissect_kafka_string(subtree, hf_kafka_client_id, tvb, pinfo, offset, api_version >= 5, NULL, NULL);

    /* client_host */
    offset = dissect_kafka_string(subtree, hf_kafka_client_host, tvb, pinfo, offset, api_version >= 5, NULL, NULL);

    /* member_metadata */
    offset = dissect_kafka_bytes(subtree, hf_kafka_member_metadata, tvb, pinfo, offset, api_version >= 5, NULL, NULL);

    /* member_assignment */
    offset = dissect_kafka_bytes(subtree, hf_kafka_member_assignment, tvb, pinfo, offset, api_version >= 5, NULL, NULL);

    if (api_version >= 5) {
        offset = dissect_kafka_tagged_fields(tvb, pinfo, subtree, offset, 0);
    }

    proto_item_set_end(subti, tvb, offset);

    if (api_version < 4) {
        proto_item_append_text(subti, " (Member=%s)",
                               kafka_tvb_get_string(pinfo->pool, tvb, member_start, member_len));

    } else {
        proto_item_append_text(subti, " (Member=%s, Instance=%s)",
                               kafka_tvb_get_string(pinfo->pool, tvb, member_start, member_len),
                               kafka_tvb_get_string(pinfo->pool, tvb, instance_start, instance_len));
    }

    return offset;
}

static int
dissect_kafka_describe_groups_response_group(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset,
                                             kafka_api_version_t api_version)
{
    proto_item *subti, *subsubti;
    proto_tree *subtree, *subsubtree;
    int group_start, group_len;

    subtree = proto_tree_add_subtree(tree, tvb, offset, -1, ett_kafka_group, &subti, "Group");

    /* error_code */
    offset = dissect_kafka_error(tvb, pinfo, subtree, offset);

    /* group_id */
    offset = dissect_kafka_string(subtree, hf_kafka_consumer_group, tvb, pinfo, offset, api_version >= 5,
                                  &group_start, &group_len);

    /* state */
    offset = dissect_kafka_string(subtree, hf_kafka_group_state, tvb, pinfo, offset, api_version >= 5, NULL, NULL);

    /* protocol_type */
    offset = dissect_kafka_string(subtree, hf_kafka_protocol_type, tvb, pinfo, offset, api_version >= 5, NULL, NULL);

    /* protocol */
    offset = dissect_kafka_string(subtree, hf_kafka_protocol_name, tvb, pinfo, offset, api_version >= 5, NULL, NULL);

    /* [member] */
    subsubtree = proto_tree_add_subtree(subtree, tvb, offset, -1, ett_kafka_group_members,
                                        &subsubti, "Members");
    offset = dissect_kafka_array(subsubtree, tvb, pinfo, offset, api_version >= 5, api_version,
                                 &dissect_kafka_describe_groups_response_member, NULL);
    proto_item_set_end(subsubti, tvb, offset);

    if (api_version >= 3) {
        offset = dissect_kafka_int32(subtree, hf_kafka_group_authorized_ops, tvb, pinfo, offset, NULL);
    }

    if (api_version >= 5) {
        offset = dissect_kafka_tagged_fields(tvb, pinfo, subtree, offset, 0);
    }

    proto_item_set_end(subti, tvb, offset);
    proto_item_append_text(subti, " (Group=%s)",
                           kafka_tvb_get_string(pinfo->pool, tvb, group_start, group_len));

    return offset;
}

static int
dissect_kafka_describe_groups_response(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset,
                                       kafka_api_version_t api_version)
{
    if (api_version >= 1) {
        offset = dissect_kafka_throttle_time(tvb, pinfo, tree, offset);
    }

    /* [group] */
    offset = dissect_kafka_array(tree, tvb, pinfo, offset, api_version >= 5, api_version,
                                 &dissect_kafka_describe_groups_response_group, NULL);

    if (api_version >= 5) {
        offset = dissect_kafka_tagged_fields(tvb, pinfo, tree, offset, 0);
    }

    return offset;
}

/* LIST_GROUPS REQUEST/RESPONSE */

static int
dissect_kafka_list_groups_request(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset,
                                  kafka_api_version_t api_version)
{

    if (api_version >= 3) {
        offset = dissect_kafka_tagged_fields(tvb, pinfo, tree, offset, 0);
    }

    return offset;
}

static int
dissect_kafka_list_groups_response_group(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset,
                                         kafka_api_version_t api_version _U_)
{
    proto_item *subti;
    proto_tree *subtree;
    int group_start, group_len;
    int protocol_type_start, protocol_type_len;

    subtree = proto_tree_add_subtree(tree, tvb, offset, -1, ett_kafka_group, &subti, "Group");

    /* group_id */
    offset = dissect_kafka_string(subtree, hf_kafka_consumer_group, tvb, pinfo, offset, api_version >= 3,
                                  &group_start, &group_len);

    /* protocol_type */
    offset = dissect_kafka_string(subtree, hf_kafka_protocol_type, tvb, pinfo, offset, api_version >= 3,
                                  &protocol_type_start, &protocol_type_len);

    if (api_version >= 3) {
        offset = dissect_kafka_tagged_fields(tvb, pinfo, subtree, offset, 0);
    }

    proto_item_set_end(subti, tvb, offset);
    proto_item_append_text(subti, " (Group-ID=%s, Protocol-Type=%s)",
                           tvb_get_string_enc(pinfo->pool, tvb,
                                              group_start, group_len, ENC_UTF_8),
                           tvb_get_string_enc(pinfo->pool, tvb,
                                              protocol_type_start, protocol_type_len, ENC_UTF_8));

    return offset;
}

static int
dissect_kafka_list_groups_response(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset,
                                   kafka_api_version_t api_version)
{
    proto_item *subti;
    proto_tree *subtree;

    if (api_version >= 1) {
        offset = dissect_kafka_throttle_time(tvb, pinfo, tree, offset);
    }

    /* error_code */
    offset = dissect_kafka_error(tvb, pinfo, tree, offset);

    /* [group] */
    subtree = proto_tree_add_subtree(tree, tvb, offset, -1, ett_kafka_groups, &subti, "Groups");
    offset = dissect_kafka_array(subtree, tvb, pinfo, offset, api_version >= 3, api_version,
                                 &dissect_kafka_list_groups_response_group, NULL);
    proto_item_set_end(subti, tvb, offset);

    if (api_version >= 3) {
        offset = dissect_kafka_tagged_fields(tvb, pinfo, tree, offset, 0);
    }

    return offset;
}

/* SASL_HANDSHAKE REQUEST/RESPONSE */

static int
dissect_kafka_sasl_handshake_request(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset,
                                     kafka_api_version_t api_version _U_)
{
    /* mechanism */
    offset = dissect_kafka_string(tree, hf_kafka_sasl_mechanism, tvb, pinfo, offset, 0, NULL, NULL);

    return offset;
}

static int
dissect_kafka_sasl_handshake_response_enabled_mechanism(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                                                        int offset, kafka_api_version_t api_version _U_)
{
    /* mechanism */
    offset = dissect_kafka_string(tree, hf_kafka_sasl_mechanism, tvb, pinfo, offset, 0, NULL, NULL);

    return offset;
}

static int
dissect_kafka_sasl_handshake_response(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset,
                                      kafka_api_version_t api_version)
{
    proto_item *subti;
    proto_tree *subtree;

    /* error_code */
    offset = dissect_kafka_error(tvb, pinfo, tree, offset);

    /* [enabled_mechanism] */
    subtree = proto_tree_add_subtree(tree, tvb, offset, -1,
                                     ett_kafka_sasl_enabled_mechanisms,
                                     &subti, "Enabled SASL Mechanisms");
    offset = dissect_kafka_array(subtree, tvb, pinfo, offset, 0, api_version,
                                 &dissect_kafka_sasl_handshake_response_enabled_mechanism, NULL);
    proto_item_set_end(subti, tvb, offset);

    return offset;
}

/* CREATE_TOPICS REQUEST/RESPONSE */

static int
dissect_kafka_create_topics_request_replica(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree,
                                            int offset, kafka_api_version_t api_version _U_)
{
    /* replica */
    proto_tree_add_item(tree, hf_kafka_replica, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;

    return offset;
}

static int
dissect_kafka_create_topics_request_replica_assignment(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                                                       int offset, kafka_api_version_t api_version)
{
    proto_item *subti;
    proto_tree *subtree;
    kafka_partition_t partition;

    subtree = proto_tree_add_subtree(tree, tvb, offset, -1,
                                     ett_kafka_replica_assignment,
                                     &subti, "Replica Assignment");

    /* partition_id */
    dissect_kafka_partition_id_ret(tvb, pinfo, subtree, offset, &partition);

    /* [replica] */
    offset = dissect_kafka_array(subtree, tvb, pinfo, offset, api_version >= 5, api_version,
                                 &dissect_kafka_create_topics_request_replica, NULL);

    if (api_version >= 5) {
        offset = dissect_kafka_tagged_fields(tvb, pinfo, tree, offset, 0);
    }

    proto_item_set_end(subti, tvb, offset);
    proto_item_append_text(subti, " (Partition-ID=%d)",
                           partition);

    return offset;
}

static int
dissect_kafka_create_topics_request_config(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                                           int offset, kafka_api_version_t api_version)
{
    proto_item *subti;
    proto_tree *subtree;
    int key_start, key_len;
    int val_start, val_len;

    subtree = proto_tree_add_subtree(tree, tvb, offset, -1,
                                     ett_kafka_config,
                                     &subti, "Config");

    /* key */
    offset = dissect_kafka_string(subtree, hf_kafka_config_key, tvb, pinfo, offset, api_version >= 5, &key_start, &key_len);

    /* value */
    offset = dissect_kafka_string(subtree, hf_kafka_config_value, tvb, pinfo, offset, api_version >= 5, &val_start, &val_len);

    if (api_version >= 5) {
        offset = dissect_kafka_tagged_fields(tvb, pinfo, subtree, offset, 0);
    }

    proto_item_set_end(subti, tvb, offset);
    proto_item_append_text(subti, " (Key=%s, Value=%s)",
                           tvb_get_string_enc(pinfo->pool, tvb,
                                              key_start, key_len, ENC_UTF_8),
                           tvb_get_string_enc(pinfo->pool, tvb,
                                              val_start, val_len, ENC_UTF_8));

    return offset;
}

static int
dissect_kafka_create_topics_request_create_topic_request(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                                                         int offset, kafka_api_version_t api_version)
{
    proto_item *subti, *subsubti;
    proto_tree *subtree, *subsubtree;
    int topic_start, topic_len;

    subtree = proto_tree_add_subtree(tree, tvb, offset, -1,
                                     ett_kafka_topic,
                                     &subti, "Create Topic Request");

    /* topic */
    offset = dissect_kafka_string(subtree, hf_kafka_topic_name, tvb, pinfo, offset, api_version >= 5, &topic_start, &topic_len);

    /* num_partitions */
    proto_tree_add_item(subtree, hf_kafka_num_partitions, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;

    /* replication_factor */
    proto_tree_add_item(subtree, hf_kafka_replication_factor, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    /* [replica_assignment] */
    subsubtree = proto_tree_add_subtree(subtree, tvb, offset, -1,
                                        ett_kafka_replica_assignment,
                                        &subsubti, "Replica Assignments");
    offset = dissect_kafka_array(subsubtree, tvb, pinfo, offset, api_version >= 5, api_version,
                                 &dissect_kafka_create_topics_request_replica_assignment, NULL);
    proto_item_set_end(subsubti, tvb, offset);

    /* [config] */
    subsubtree = proto_tree_add_subtree(subtree, tvb, offset, -1,
                                        ett_kafka_config,
                                        &subsubti, "Configs");
    offset = dissect_kafka_array(subsubtree, tvb, pinfo, offset, api_version >= 5, api_version,
                                 &dissect_kafka_create_topics_request_config, NULL);
    proto_item_set_end(subsubti, tvb, offset);

    if (api_version >= 5) {
        offset = dissect_kafka_tagged_fields(tvb, pinfo, tree, offset, 0);
    }

    proto_item_set_end(subti, tvb, offset);
    proto_item_append_text(subti, " (Topic=%s)",
                           tvb_get_string_enc(pinfo->pool, tvb,
                                              topic_start, topic_len, ENC_UTF_8));

    return offset;
}

static int
dissect_kafka_create_topics_request(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset,
                                    kafka_api_version_t api_version)
{
    proto_item *subti;
    proto_tree *subtree;

    /* [topic] */
    subtree = proto_tree_add_subtree(tree, tvb, offset, -1,
                                     ett_kafka_topics,
                                     &subti, "Create Topic Requests");
    offset = dissect_kafka_array(subtree, tvb, pinfo, offset, api_version >= 5, api_version,
                                 &dissect_kafka_create_topics_request_create_topic_request, NULL);
    proto_item_set_end(subti, tvb, offset);

    /* timeout */
    proto_tree_add_item(tree, hf_kafka_timeout, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;

    if (api_version >= 1) {
        /* validate */
        proto_tree_add_item(tree, hf_kafka_validate_only, tvb, offset, 1, ENC_NA);
        offset += 1;
    }

    if (api_version >= 5) {
        offset = dissect_kafka_tagged_fields(tvb, pinfo, tree, offset, 0);
    }

    return offset;
}

static int
dissect_kafka_create_topics_response_topic_config(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                                                      int offset, kafka_api_version_t api_version)
{
    proto_item *subti;
    proto_tree *subtree;

    subtree = proto_tree_add_subtree(tree, tvb, offset, -1,
                                     ett_kafka_config_entry,
                                     &subti, "Config Entry");

    offset = dissect_kafka_string(subtree, hf_kafka_config_key, tvb, pinfo, offset, api_version >= 5, NULL, NULL);

    offset = dissect_kafka_string(subtree, hf_kafka_config_value, tvb, pinfo, offset, api_version >= 5, NULL, NULL);

    offset = dissect_kafka_int8(subtree, hf_kafka_config_readonly, tvb, pinfo, offset, NULL);

    offset = dissect_kafka_int8(subtree, hf_kafka_config_source, tvb, pinfo, offset, NULL);

    offset = dissect_kafka_int8(subtree, hf_kafka_config_sensitive, tvb, pinfo, offset, NULL);

    offset = dissect_kafka_tagged_fields(tvb, pinfo, subtree, offset, 0);

    proto_item_set_end(subti, tvb, offset);

    return offset;

}

static int
dissect_kafka_create_topics_response_topic(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                                                      int offset, kafka_api_version_t api_version)
{
    proto_item *subti, *subsubti;
    proto_tree *subtree, *subsubtree;
    int topic_start, topic_len;
    kafka_error_t error;

    subtree = proto_tree_add_subtree(tree, tvb, offset, -1,
                                     ett_kafka_topic,
                                     &subti, "Topic");

    /* topic */
    offset = dissect_kafka_string(subtree, hf_kafka_topic_name, tvb, pinfo, offset, api_version >= 5, &topic_start, &topic_len);

    /* topic_id */
    if (api_version >= 7) {
        offset = dissect_kafka_uuid(subtree, hf_kafka_topic_id, tvb, pinfo, offset);
    }

    /* error_code */
    offset = dissect_kafka_error_ret(tvb, pinfo, subtree, offset, &error);

    if (api_version >= 1) {
        offset = dissect_kafka_string(subtree, hf_kafka_error_message, tvb, pinfo, offset, api_version >= 5, NULL, NULL);
    }

    if (api_version >= 5) {
        offset = dissect_kafka_int32(subtree, hf_kafka_num_partitions, tvb, pinfo, offset, NULL);
    }

    if (api_version >= 5) {
        offset = dissect_kafka_int16(subtree, hf_kafka_replication_factor, tvb, pinfo, offset, NULL);
    }

    if (api_version >= 5) {
        subsubtree = proto_tree_add_subtree(subtree, tvb, offset, -1,
                                            ett_kafka_config,
                                            &subsubti, "Config");
        offset = dissect_kafka_array(subsubtree, tvb, pinfo, offset, api_version >= 5, api_version,
                                     &dissect_kafka_create_topics_response_topic_config, NULL);
        proto_item_set_end(subsubti, tvb, offset);
    }

    if (api_version >= 5) {
        offset = dissect_kafka_tagged_fields(tvb, pinfo, tree, offset, 0);
    }

    proto_item_set_end(subti, tvb, offset);
    proto_item_append_text(subti, " (Topic=%s, Error=%s)",
                           kafka_tvb_get_string(pinfo->pool, tvb, topic_start, topic_len),
                           kafka_error_to_str(error));

    return offset;
}

static int
dissect_kafka_create_topics_response(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset,
                                     kafka_api_version_t api_version)
{
    proto_item *subti;
    proto_tree *subtree;

    if (api_version >= 2) {
        offset = dissect_kafka_throttle_time(tvb, pinfo, tree, offset);
    }

    /* [topic_error_code] */
    subtree = proto_tree_add_subtree(tree, tvb, offset, -1,
                                     ett_kafka_topics,
                                     &subti, "Topics");
    offset = dissect_kafka_array(subtree, tvb, pinfo, offset, api_version >= 5, api_version,
                                 &dissect_kafka_create_topics_response_topic, NULL);
    proto_item_set_end(subti, tvb, offset);

    if (api_version >= 5) {
        offset = dissect_kafka_tagged_fields(tvb, pinfo, tree, offset, 0);
    }

    return offset;
}

/* DELETE_TOPICS REQUEST/RESPONSE */

static int
dissect_kafka_delete_topics_request_topic(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                                          int offset, kafka_api_version_t api_version)
{
    proto_item *subti;
    proto_tree *subtree;

    subtree = proto_tree_add_subtree(tree, tvb, offset, -1,
                                     ett_kafka_topics,
                                     &subti, "Topic");

    if (api_version >= 6) {
        /* topic_name */
        offset = dissect_kafka_string(subtree, hf_kafka_topic_name, tvb, pinfo, offset, api_version >= 4, NULL, NULL);

        /* topic_id */
        offset = dissect_kafka_uuid(subtree, hf_kafka_topic_id, tvb, pinfo, offset);
    }

    proto_item_set_end(subti, tvb, offset);

    return offset;
}

static int
dissect_kafka_delete_topics_request_topic_name(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                                               int offset, kafka_api_version_t api_version)
{
    /* topic */
    offset = dissect_kafka_string(tree, hf_kafka_topic_name, tvb, pinfo, offset, api_version >= 4, NULL, NULL);

    return offset;
}

static int
dissect_kafka_delete_topics_request(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset,
                                    kafka_api_version_t api_version)
{
    proto_item *subti;
    proto_tree *subtree;

    /* [topic] */
    if (api_version >= 6) {
        subtree = proto_tree_add_subtree(tree, tvb, offset, -1,
                                         ett_kafka_topics,
                                         &subti, "Topics");

        offset = dissect_kafka_array(subtree, tvb, pinfo, offset, api_version >= 4, api_version,
                                     &dissect_kafka_delete_topics_request_topic, NULL);

        if (api_version >= 4) {
            offset = dissect_kafka_tagged_fields(tvb, pinfo, subtree, offset, 0);
        }

        proto_item_set_end(subti, tvb, offset);
    }

    /* [topic_names] */
    if (api_version >= 0 && api_version <= 5) {
        subtree = proto_tree_add_subtree(tree, tvb, offset, -1,
                                         ett_kafka_topics,
                                         &subti, "Topics");

        offset = dissect_kafka_array(subtree, tvb, pinfo, offset, api_version >= 4, api_version,
                                     &dissect_kafka_delete_topics_request_topic_name, NULL);

        proto_item_set_end(subti, tvb, offset);
    }

    /* timeout */
    proto_tree_add_item(tree, hf_kafka_timeout, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;

    if (api_version >= 4) {
        offset = dissect_kafka_tagged_fields(tvb, pinfo, tree, offset, 0);
    }

    return offset;
}

static int
dissect_kafka_delete_topics_response_topic_error_code(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                                                      int offset, kafka_api_version_t api_version)
{
    proto_item *subti;
    proto_tree *subtree;
    int topic_start, topic_len;
    kafka_error_t error;

    subtree = proto_tree_add_subtree(tree, tvb, offset, -1,
                                     ett_kafka_topic,
                                     &subti, "Topic Error Code");

    /* topic */
    offset = dissect_kafka_string(subtree, hf_kafka_topic_name, tvb, pinfo, offset, api_version >= 4, &topic_start, &topic_len);

    /* topic_id */
    if (api_version >= 6) {
        offset = dissect_kafka_uuid(subtree, hf_kafka_topic_id, tvb, pinfo, offset);
    }

    /* error_code */
    offset = dissect_kafka_error_ret(tvb, pinfo, subtree, offset, &error);

    /* error_message */
    if (api_version >= 5) {
        offset = dissect_kafka_string(subtree, hf_kafka_error_message, tvb, pinfo, offset, api_version >= 4, NULL, NULL);
    }

    if (api_version >= 4) {
        offset = dissect_kafka_tagged_fields(tvb, pinfo, subtree, offset, 0);
    }

    proto_item_set_end(subti, tvb, offset);
    proto_item_append_text(subti, " (Topic=%s, Error=%s)",
                           tvb_get_string_enc(pinfo->pool, tvb,
                                              topic_start, topic_len, ENC_UTF_8),
                           kafka_error_to_str(error));

    return offset;
}

static int
dissect_kafka_delete_topics_response(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset,
                                     kafka_api_version_t api_version)
{
    proto_item *subti;
    proto_tree *subtree;

    if (api_version >= 3) {
        offset = dissect_kafka_throttle_time(tvb, pinfo, tree, offset);
    }

    /* [topic_error_code] */
    subtree = proto_tree_add_subtree(tree, tvb, offset, -1,
                                     ett_kafka_topics,
                                     &subti, "Topic Error Codes");
    offset = dissect_kafka_array(subtree, tvb, pinfo, offset, api_version >= 4, api_version,
                                 &dissect_kafka_delete_topics_response_topic_error_code, NULL);
    proto_item_set_end(subti, tvb, offset);

    if (api_version >= 4) {
        offset = dissect_kafka_tagged_fields(tvb, pinfo, tree, offset, 0);
    }

    return offset;
}

/* DELETE_RECORDS REQUEST/RESPONSE */

static int
dissect_kafka_delete_records_request_topic_partition(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree,
                                           int offset, kafka_api_version_t api_version _U_)
{
    uint32_t partition_id;
    int64_t partition_offset;
    proto_item *subti;
    proto_tree *subtree;

    subtree = proto_tree_add_subtree(tree, tvb, offset, -1, ett_kafka_partition, &subti, "Partition");

    partition_id = tvb_get_ntohl(tvb, offset);
    proto_tree_add_item(subtree, hf_kafka_partition_id, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;

    partition_offset = tvb_get_ntohi64(tvb, offset);
    proto_tree_add_item(subtree, hf_kafka_offset, tvb, offset, 8, ENC_BIG_ENDIAN);
    offset += 8;

    proto_item_set_end(subti, tvb, offset);

    if (partition_offset == -1) {
        proto_item_append_text(subti, " (ID=%u, Offset=HWM)", partition_id);
    } else {
        proto_item_append_text(subti, " (ID=%u, Offset=%" PRIi64 ")", partition_id, partition_offset);
    }

    return offset;
}

static int
dissect_kafka_delete_records_request_topic(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                                          int offset, kafka_api_version_t api_version _U_)
{
    int topic_start, topic_len;
    proto_item *subti, *subsubti;
    proto_tree *subtree, *subsubtree;

    subtree = proto_tree_add_subtree(tree, tvb, offset, -1, ett_kafka_topic, &subti, "Topic");

    offset = dissect_kafka_string(subtree, hf_kafka_topic_name, tvb, pinfo, offset, 0, &topic_start, &topic_len);

    subsubtree = proto_tree_add_subtree(subtree, tvb, offset, -1, ett_kafka_partitions, &subsubti, "Partitions");
    offset = dissect_kafka_array(subsubtree, tvb, pinfo, offset, 0, api_version,
                                 &dissect_kafka_delete_records_request_topic_partition, NULL);
    proto_item_set_end(subsubti, tvb, offset);

    proto_item_set_end(subti, tvb, offset);
    proto_item_append_text(subti, " (Topic=%s)",
                           tvb_get_string_enc(pinfo->pool, tvb,
                                              topic_start, topic_len, ENC_UTF_8));

    return offset;
}

static int
dissect_kafka_delete_records_request(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset,
                                    kafka_api_version_t api_version)
{
    proto_item *subti;
    proto_tree *subtree;

    /* [topic] */
    subtree = proto_tree_add_subtree(tree, tvb, offset, -1,
                                     ett_kafka_topics,
                                     &subti, "Topics");
    offset = dissect_kafka_array(subtree, tvb, pinfo, offset, 0, api_version,
                                 &dissect_kafka_delete_records_request_topic, NULL);
    proto_item_set_end(subti, tvb, offset);

    /* timeout */
    proto_tree_add_item(tree, hf_kafka_timeout, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;

    return offset;
}

static int
dissect_kafka_delete_records_response_topic_partition(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree,
                                                     int offset, kafka_api_version_t api_version _U_)
{
    uint32_t partition_id;
    int64_t partition_offset; // low watermark
    kafka_error_t partition_error_code;

    proto_item *subti;
    proto_tree *subtree;

    subtree = proto_tree_add_subtree(tree, tvb, offset, -1, ett_kafka_partition, &subti, "Partition");

    partition_id = tvb_get_ntohl(tvb, offset);
    proto_tree_add_item(subtree, hf_kafka_partition_id, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;

    partition_offset = tvb_get_ntohi64(tvb, offset);
    proto_tree_add_item(subtree, hf_kafka_offset, tvb, offset, 8, ENC_BIG_ENDIAN);
    offset += 8;

    partition_error_code = (kafka_error_t) tvb_get_ntohs(tvb, offset);
    proto_tree_add_item(subtree, hf_kafka_error, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    proto_item_set_end(subti, tvb, offset);

    if (partition_error_code == 0) {
        proto_item_append_text(subti, " (ID=%u, Offset=%" PRIi64 ")", partition_id, partition_offset);
    } else {
        proto_item_append_text(subti, " (ID=%u, Error=%s)", partition_id, kafka_error_to_str(partition_error_code));
    }

    return offset;
}

static int
dissect_kafka_delete_records_response_topic(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                                           int offset, kafka_api_version_t api_version _U_)
{
    int topic_start, topic_len;
    proto_item *subti, *subsubti;
    proto_tree *subtree, *subsubtree;

    subtree = proto_tree_add_subtree(tree, tvb, offset, -1, ett_kafka_topic, &subti, "Topic");

    offset = dissect_kafka_string(subtree, hf_kafka_topic_name, tvb, pinfo, offset, 0, &topic_start, &topic_len);

    subsubtree = proto_tree_add_subtree(subtree, tvb, offset, -1, ett_kafka_partitions, &subsubti, "Partitions");
    offset = dissect_kafka_array(subsubtree, tvb, pinfo, offset, 0, api_version,
                                 &dissect_kafka_delete_records_response_topic_partition, NULL);
    proto_item_set_end(subsubti, tvb, offset);

    proto_item_set_end(subti, tvb, offset);
    proto_item_append_text(subti, " (Topic=%s)",
                           tvb_get_string_enc(pinfo->pool, tvb,
                                              topic_start, topic_len, ENC_UTF_8));

    return offset;
}


static int
dissect_kafka_delete_records_response(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset,
                                     kafka_api_version_t api_version)
{
    proto_item *subti;
    proto_tree *subtree;

    offset = dissect_kafka_throttle_time(tvb, pinfo, tree, offset);

    /* [topic_error_code] */
    subtree = proto_tree_add_subtree(tree, tvb, offset, -1,
                                     ett_kafka_topics,
                                     &subti, "Topics");
    offset = dissect_kafka_array(subtree, tvb, pinfo, offset, 0, api_version,
                                 &dissect_kafka_delete_records_response_topic, NULL);

    proto_item_set_end(subti, tvb, offset);

    return offset;
}

/* INIT_PRODUCER_ID REQUEST/RESPONSE */

static int
dissect_kafka_init_producer_id_request(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset,
                              kafka_api_version_t api_version)
{

    offset = dissect_kafka_string(tree, hf_kafka_transactional_id, tvb, pinfo, offset, api_version >= 2, NULL, NULL);

    proto_tree_add_item(tree, hf_kafka_transaction_timeout, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;

    if (api_version >= 3) {
        proto_tree_add_item(tree, hf_kafka_producer_id, tvb, offset, 8, ENC_BIG_ENDIAN);
        offset += 8;
    }

    if (api_version >= 3) {
        proto_tree_add_item(tree, hf_kafka_producer_epoch, tvb, offset, 2, ENC_BIG_ENDIAN);
        offset += 2;
    }

    if (api_version >= 2) {
        offset = dissect_kafka_tagged_fields(tvb, pinfo, tree, offset, 0);
    }

    return offset;
}


static int
dissect_kafka_init_producer_id_response(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset,
                               kafka_api_version_t api_version)
{
    offset = dissect_kafka_throttle_time(tvb, pinfo, tree, offset);

    offset = dissect_kafka_error(tvb, pinfo, tree, offset);

    proto_tree_add_item(tree, hf_kafka_producer_id, tvb, offset, 8, ENC_BIG_ENDIAN);
    offset += 8;

    proto_tree_add_item(tree, hf_kafka_producer_epoch, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    if (api_version >= 2) {
        offset = dissect_kafka_tagged_fields(tvb, pinfo, tree, offset, 0);
    }

    return offset;
}

/* OFFSET_FOR_LEADER_EPOCH REQUEST/RESPONSE */

static int
dissect_kafka_offset_for_leader_epoch_request_topic_partition(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree,
                                                            int offset, kafka_api_version_t api_version)
{
    uint32_t partition_id;
    proto_item *subti;
    proto_tree *subtree;

    subtree = proto_tree_add_subtree(tree, tvb, offset, -1, ett_kafka_partition, &subti, "Partition");

    partition_id = tvb_get_ntohl(tvb, offset);
    proto_tree_add_item(subtree, hf_kafka_partition_id, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;

    if (api_version >= 2) {
        proto_tree_add_item(subtree, hf_kafka_current_leader_epoch, tvb, offset, 4, ENC_BIG_ENDIAN);
        offset += 4;
    }

    proto_tree_add_item(subtree, hf_kafka_leader_epoch, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;

    proto_item_set_end(subti, tvb, offset);

    proto_item_append_text(subti, " (ID=%u)", partition_id);

    return offset;
}

static int
dissect_kafka_offset_for_leader_epoch_request_topic(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                                                  int offset, kafka_api_version_t api_version _U_)
{
    int topic_start, topic_len;
    proto_item *subti, *subsubti;
    proto_tree *subtree, *subsubtree;

    subtree = proto_tree_add_subtree(tree, tvb, offset, -1, ett_kafka_topic, &subti, "Topic");

    offset = dissect_kafka_string(subtree, hf_kafka_topic_name, tvb, pinfo, offset, 0, &topic_start, &topic_len);

    subsubtree = proto_tree_add_subtree(subtree, tvb, offset, -1, ett_kafka_partitions, &subsubti, "Partitions");
    offset = dissect_kafka_array(subsubtree, tvb, pinfo, offset, 0, api_version,
                                 &dissect_kafka_offset_for_leader_epoch_request_topic_partition, NULL);
    proto_item_set_end(subsubti, tvb, offset);

    proto_item_set_end(subti, tvb, offset);
    proto_item_append_text(subti, " (Name=%s)",
                           tvb_get_string_enc(pinfo->pool, tvb,
                                              topic_start, topic_len, ENC_UTF_8));

    return offset;
}

static int
dissect_kafka_offset_for_leader_epoch_request(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset,
                                            kafka_api_version_t api_version)
{
    proto_item *subti;
    proto_tree *subtree;
    int32_t replica_id;

    if (api_version >= 3) {
        replica_id = tvb_get_ntohl(tvb, offset);
        subti = proto_tree_add_item(tree, hf_kafka_replica, tvb, offset, 4, ENC_BIG_ENDIAN);
        if (replica_id==-2) {
            proto_item_append_text(subti, " (debug)");
        } else if (replica_id==-1) {
            proto_item_append_text(subti, " (consumer)");
        }
        offset += 4;
    }

    /* [topic] */
    subtree = proto_tree_add_subtree(tree, tvb, offset, -1,
                                     ett_kafka_topics,
                                     &subti, "Topics");
    offset = dissect_kafka_array(subtree, tvb, pinfo, offset, 0, api_version,
                                 &dissect_kafka_offset_for_leader_epoch_request_topic, NULL);
    proto_item_set_end(subti, tvb, offset);

    return offset;
}

static int
dissect_kafka_offset_for_leader_epoch_response_topic_partition(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree,
                                                             int offset, kafka_api_version_t api_version _U_)
{
    uint32_t partition_id;
    kafka_error_t partition_error_code;

    proto_item *subti;
    proto_tree *subtree;

    subtree = proto_tree_add_subtree(tree, tvb, offset, -1, ett_kafka_partition, &subti, "Partition");

    partition_error_code = (kafka_error_t) tvb_get_ntohs(tvb, offset);
    proto_tree_add_item(subtree, hf_kafka_error, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    partition_id = tvb_get_ntohl(tvb, offset);
    proto_tree_add_item(subtree, hf_kafka_partition_id, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;

    if (api_version >= 1) {
        proto_tree_add_item(subtree, hf_kafka_leader_epoch, tvb, offset, 4, ENC_BIG_ENDIAN);
        offset += 4;
    }

    proto_tree_add_item(subtree, hf_kafka_offset, tvb, offset, 8, ENC_BIG_ENDIAN);
    offset += 8;

    proto_item_set_end(subti, tvb, offset);

    if (partition_error_code == 0) {
        proto_item_append_text(subti, " (ID=%u)", partition_id);
    } else {
        proto_item_append_text(subti, " (ID=%u, Error=%s)", partition_id, kafka_error_to_str(partition_error_code));
    }

    return offset;
}

static int
dissect_kafka_offset_for_leader_epoch_response_topic(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                                                   int offset, kafka_api_version_t api_version _U_)
{
    int topic_start, topic_len;
    proto_item *subti, *subsubti;
    proto_tree *subtree, *subsubtree;

    subtree = proto_tree_add_subtree(tree, tvb, offset, -1, ett_kafka_topic, &subti, "Topic");

    offset = dissect_kafka_string(subtree, hf_kafka_topic_name, tvb, pinfo, offset, 0, &topic_start, &topic_len);

    subsubtree = proto_tree_add_subtree(subtree, tvb, offset, -1, ett_kafka_partitions, &subsubti, "Partitions");
    offset = dissect_kafka_array(subsubtree, tvb, pinfo, offset, 0, api_version,
                                 &dissect_kafka_offset_for_leader_epoch_response_topic_partition, NULL);
    proto_item_set_end(subsubti, tvb, offset);

    proto_item_set_end(subti, tvb, offset);
    proto_item_append_text(subti, " (Name=%s)",
                           tvb_get_string_enc(pinfo->pool, tvb,
                                              topic_start, topic_len, ENC_UTF_8));

    return offset;
}


static int
dissect_kafka_offset_for_leader_epoch_response(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset,
                                             kafka_api_version_t api_version)
{
    proto_item *subti;
    proto_tree *subtree;

    if (api_version >= 2) {
        offset = dissect_kafka_throttle_time(tvb, pinfo, tree, offset);
    }

    subtree = proto_tree_add_subtree(tree, tvb, offset, -1,
                                     ett_kafka_topics,
                                     &subti, "Topics");
    offset = dissect_kafka_array(subtree, tvb, pinfo, offset, 0, api_version,
                                 &dissect_kafka_offset_for_leader_epoch_response_topic, NULL);

    proto_item_set_end(subti, tvb, offset);

    return offset;
}

/* ADD_PARTITIONS_TO_TXN REQUEST/RESPONSE */

static int
dissect_kafka_add_partitions_to_txn_request_topic_partition(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree,
                                                     int offset, kafka_api_version_t api_version _U_)
{
    proto_tree_add_item(tree, hf_kafka_partition_id, tvb, offset, 4, ENC_BIG_ENDIAN);

    return offset+4;
}

static int
dissect_kafka_add_partitions_to_txn_request_topic(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                                           int offset, kafka_api_version_t api_version _U_)
{
    int topic_start, topic_len;
    proto_item *subti, *subsubti;
    proto_tree *subtree, *subsubtree;

    subtree = proto_tree_add_subtree(tree, tvb, offset, -1, ett_kafka_topic, &subti, "Topic");

    offset = dissect_kafka_string(subtree, hf_kafka_topic_name, tvb, pinfo, offset, 0, &topic_start, &topic_len);

    subsubtree = proto_tree_add_subtree(subtree, tvb, offset, -1, ett_kafka_partitions, &subsubti, "Partitions");
    offset = dissect_kafka_array(subsubtree, tvb, pinfo, offset, 0, api_version,
                                 &dissect_kafka_add_partitions_to_txn_request_topic_partition, NULL);
    proto_item_set_end(subsubti, tvb, offset);

    proto_item_set_end(subti, tvb, offset);
    proto_item_append_text(subti, " (Topic=%s)",
                           tvb_get_string_enc(pinfo->pool, tvb,
                                              topic_start, topic_len, ENC_UTF_8));

    return offset;
}

static int
dissect_kafka_add_partitions_to_txn_request(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset,
                                     kafka_api_version_t api_version)
{
    proto_item *subti;
    proto_tree *subtree;

    offset = dissect_kafka_string(tree, hf_kafka_transactional_id, tvb, pinfo, offset, 0, NULL, NULL);

    proto_tree_add_item(tree, hf_kafka_producer_id, tvb, offset, 8, ENC_BIG_ENDIAN);
    offset += 8;

    proto_tree_add_item(tree, hf_kafka_producer_epoch, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    /* [topic] */
    subtree = proto_tree_add_subtree(tree, tvb, offset, -1,
                                     ett_kafka_topics,
                                     &subti, "Topics");
    offset = dissect_kafka_array(subtree, tvb, pinfo, offset, 0, api_version,
                                 &dissect_kafka_add_partitions_to_txn_request_topic, NULL);
    proto_item_set_end(subti, tvb, offset);

    return offset;
}

static int
dissect_kafka_add_partitions_to_txn_response_topic_partition(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree,
                                                      int offset, kafka_api_version_t api_version _U_)
{
    uint32_t partition_id;
    kafka_error_t partition_error_code;

    proto_item *subti;
    proto_tree *subtree;

    subtree = proto_tree_add_subtree(tree, tvb, offset, -1, ett_kafka_partition, &subti, "Partition");

    partition_id = tvb_get_ntohl(tvb, offset);
    proto_tree_add_item(subtree, hf_kafka_partition_id, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;

    partition_error_code = (kafka_error_t) tvb_get_ntohs(tvb, offset);
    proto_tree_add_item(subtree, hf_kafka_error, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    proto_item_set_end(subti, tvb, offset);

    if (partition_error_code == 0) {
        proto_item_append_text(subti, " (ID=%u)", partition_id);
    } else {
        proto_item_append_text(subti, " (ID=%u, Error=%s)", partition_id, kafka_error_to_str(partition_error_code));
    }

    return offset;
}

static int
dissect_kafka_add_partitions_to_txn_response_topic(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                                            int offset, kafka_api_version_t api_version _U_)
{
    int topic_start, topic_len;
    proto_item *subti, *subsubti;
    proto_tree *subtree, *subsubtree;

    subtree = proto_tree_add_subtree(tree, tvb, offset, -1, ett_kafka_topic, &subti, "Topic");

    offset = dissect_kafka_string(subtree, hf_kafka_topic_name, tvb, pinfo, offset, 0, &topic_start, &topic_len);

    subsubtree = proto_tree_add_subtree(subtree, tvb, offset, -1, ett_kafka_partitions, &subsubti, "Partitions");
    offset = dissect_kafka_array(subsubtree, tvb, pinfo, offset, 0, api_version,
                                 &dissect_kafka_add_partitions_to_txn_response_topic_partition, NULL);
    proto_item_set_end(subsubti, tvb, offset);

    proto_item_set_end(subti, tvb, offset);
    proto_item_append_text(subti, " (Topic=%s)",
                           tvb_get_string_enc(pinfo->pool, tvb,
                                              topic_start, topic_len, ENC_UTF_8));

    return offset;
}


static int
dissect_kafka_add_partitions_to_txn_response(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset,
                                      kafka_api_version_t api_version)
{
    proto_item *subti;
    proto_tree *subtree;

    offset = dissect_kafka_throttle_time(tvb, pinfo, tree, offset);

    subtree = proto_tree_add_subtree(tree, tvb, offset, -1,
                                     ett_kafka_topics,
                                     &subti, "Topics");
    offset = dissect_kafka_array(subtree, tvb, pinfo, offset, 0, api_version,
                                 &dissect_kafka_add_partitions_to_txn_response_topic, NULL);

    proto_item_set_end(subti, tvb, offset);

    return offset;
}

/* ADD_OFFSETS_TO_TXN REQUEST/RESPONSE */

static int
dissect_kafka_add_offsets_to_txn_request(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset,
                              kafka_api_version_t api_version _U_)
{
    offset = dissect_kafka_string(tree, hf_kafka_transactional_id, tvb, pinfo, offset, 0, NULL, NULL);

    proto_tree_add_item(tree, hf_kafka_producer_id, tvb, offset, 8, ENC_BIG_ENDIAN);
    offset += 8;

    proto_tree_add_item(tree, hf_kafka_producer_epoch, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    offset = dissect_kafka_string(tree, hf_kafka_consumer_group, tvb, pinfo, offset, 0, NULL, NULL);

    return offset;
}


static int
dissect_kafka_add_offsets_to_txn_response(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset,
                               kafka_api_version_t api_version _U_)
{
    offset = dissect_kafka_throttle_time(tvb, pinfo, tree, offset);

    offset = dissect_kafka_error(tvb, pinfo, tree, offset);

    return offset;
}

/* END_TXN REQUEST/RESPONSE */

static int
dissect_kafka_end_txn_request(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset,
                                            kafka_api_version_t api_version _U_)
{
    offset = dissect_kafka_string(tree, hf_kafka_transactional_id, tvb, pinfo, offset, 0, NULL, NULL);

    proto_tree_add_item(tree, hf_kafka_producer_id, tvb, offset, 8, ENC_BIG_ENDIAN);
    offset += 8;

    proto_tree_add_item(tree, hf_kafka_producer_epoch, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    proto_tree_add_item(tree, hf_kafka_transaction_result, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;

    return offset;
}


static int
dissect_kafka_end_txn_response(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset,
                                             kafka_api_version_t api_version _U_)
{
    offset = dissect_kafka_throttle_time(tvb, pinfo, tree, offset);

    offset = dissect_kafka_error(tvb, pinfo, tree, offset);

    return offset;
}

/* WRITE_TXN_MARKERS REQUEST/RESPONSE */

static int
dissect_kafka_write_txn_markers_request_partition(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree,
                                                     int offset, kafka_api_version_t api_version _U_)
{
    proto_tree_add_item(tree, hf_kafka_partition_id, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;

    return offset;
}

static int
dissect_kafka_write_txn_markers_request_topic(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                                           int offset, kafka_api_version_t api_version)
{
    int topic_start, topic_len;
    proto_item *subti, *subsubti;
    proto_tree *subtree, *subsubtree;

    subtree = proto_tree_add_subtree(tree, tvb, offset, -1, ett_kafka_topic, &subti, "Topic");

    offset = dissect_kafka_string(subtree, hf_kafka_topic_name, tvb, pinfo, offset, 0, &topic_start, &topic_len);

    subsubtree = proto_tree_add_subtree(subtree, tvb, offset, -1, ett_kafka_partitions, &subsubti, "Partitions");
    offset = dissect_kafka_array(subsubtree, tvb, pinfo, offset, 0, api_version,
                                 &dissect_kafka_write_txn_markers_request_partition, NULL);
    proto_item_set_end(subsubti, tvb, offset);

    proto_item_set_end(subti, tvb, offset);
    proto_item_append_text(subti, " (Topic=%s)",
                           tvb_get_string_enc(pinfo->pool, tvb,
                                              topic_start, topic_len, ENC_UTF_8));

    return offset;
}

static int
dissect_kafka_write_txn_markers_request_marker(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset,
                                     kafka_api_version_t api_version)
{
    uint64_t producer_id;
    proto_item *subti, *subsubti;
    proto_tree *subtree, *subsubtree;

    subtree = proto_tree_add_subtree(tree, tvb, offset, -1,
                                     ett_kafka_marker,
                                     &subti, "Marker");

    producer_id = tvb_get_ntoh64(tvb, offset);
    proto_tree_add_item(subtree, hf_kafka_producer_id, tvb, offset, 8, ENC_BIG_ENDIAN);
    offset += 8;

    proto_tree_add_item(subtree, hf_kafka_producer_epoch, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    proto_tree_add_item(subtree, hf_kafka_transaction_result, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;

    subsubtree = proto_tree_add_subtree(subtree, tvb, offset, -1,
                                     ett_kafka_topics,
                                     &subsubti, "Topics");
    offset = dissect_kafka_array(subsubtree, tvb, pinfo, offset, 0, api_version,
                                 &dissect_kafka_write_txn_markers_request_topic, NULL);

    proto_tree_add_item(subsubtree, hf_kafka_coordinator_epoch, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;

    proto_item_set_end(subsubti, tvb, offset);
    proto_item_set_end(subti, tvb, offset);
    proto_item_append_text(subti, " (Producer=%" PRIu64 ")", producer_id);

    return offset;
}

static int
dissect_kafka_write_txn_markers_request(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset,
                                                kafka_api_version_t api_version)
{
    proto_item *subti;
    proto_tree *subtree;

    /* [topic] */
    subtree = proto_tree_add_subtree(tree, tvb, offset, -1,
                                     ett_kafka_markers,
                                     &subti, "Markers");
    offset = dissect_kafka_array(subtree, tvb, pinfo, offset, 0, api_version,
                                 &dissect_kafka_write_txn_markers_request_marker, NULL);
    proto_item_set_end(subti, tvb, offset);

    return offset;
}

static int
dissect_kafka_write_txn_markers_response_partition(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree,
                                                      int offset, kafka_api_version_t api_version _U_)
{
    uint32_t partition_id;
    kafka_error_t partition_error_code;

    proto_item *subti;
    proto_tree *subtree;

    subtree = proto_tree_add_subtree(tree, tvb, offset, -1, ett_kafka_partition, &subti, "Partition");

    partition_id = tvb_get_ntohl(tvb, offset);
    proto_tree_add_item(subtree, hf_kafka_partition_id, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;

    partition_error_code = (kafka_error_t) tvb_get_ntohs(tvb, offset);
    proto_tree_add_item(subtree, hf_kafka_error, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    proto_item_set_end(subti, tvb, offset);

    if (partition_error_code == 0) {
        proto_item_append_text(subti, " (ID=%u", partition_id);
    } else {
        proto_item_append_text(subti, " (ID=%u, Error=%s)", partition_id, kafka_error_to_str(partition_error_code));
    }

    return offset;
}

static int
dissect_kafka_write_txn_markers_response_topic(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                                            int offset, kafka_api_version_t api_version _U_)
{
    int topic_start, topic_len;
    proto_item *subti, *subsubti;
    proto_tree *subtree, *subsubtree;

    subtree = proto_tree_add_subtree(tree, tvb, offset, -1, ett_kafka_topic, &subti, "Topic");

    offset = dissect_kafka_string(subtree, hf_kafka_topic_name, tvb, pinfo, offset, 0, &topic_start, &topic_len);

    subsubtree = proto_tree_add_subtree(subtree, tvb, offset, -1, ett_kafka_partitions, &subsubti, "Partitions");
    offset = dissect_kafka_array(subsubtree, tvb, pinfo, offset, 0, api_version,
                                 &dissect_kafka_write_txn_markers_response_partition, NULL);
    proto_item_set_end(subsubti, tvb, offset);

    proto_item_set_end(subti, tvb, offset);
    proto_item_append_text(subti, " (Topic=%s)",
                           tvb_get_string_enc(pinfo->pool, tvb,
                                              topic_start, topic_len, ENC_UTF_8));

    return offset;
}

static int
dissect_kafka_write_txn_markers_response_marker(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                                               int offset, kafka_api_version_t api_version _U_)
{
    uint64_t producer_id;
    proto_item *subti, *subsubti;
    proto_tree *subtree, *subsubtree;

    subtree = proto_tree_add_subtree(tree, tvb, offset, -1, ett_kafka_marker, &subti, "Marker");

    producer_id = tvb_get_ntoh64(tvb, offset);
    proto_tree_add_item(subtree, hf_kafka_producer_id, tvb, offset, 8, ENC_BIG_ENDIAN);
    offset += 8;

    subsubtree = proto_tree_add_subtree(subtree, tvb, offset, -1, ett_kafka_partitions, &subsubti, "Topics");
    offset = dissect_kafka_array(subsubtree, tvb, pinfo, offset, 0, api_version,
                                 &dissect_kafka_write_txn_markers_response_topic, NULL);
    proto_item_set_end(subsubti, tvb, offset);

    proto_item_set_end(subti, tvb, offset);
    proto_item_append_text(subti, " (Producer=%" PRIu64 ")", producer_id);

    return offset;
}

static int
dissect_kafka_write_txn_markers_response(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset,
                                      kafka_api_version_t api_version)
{
    proto_item *subti;
    proto_tree *subtree;

    offset = dissect_kafka_throttle_time(tvb, pinfo, tree, offset);

    subtree = proto_tree_add_subtree(tree, tvb, offset, -1,
                                     ett_kafka_markers,
                                     &subti, "Markers");
    offset = dissect_kafka_array(subtree, tvb, pinfo, offset, 0, api_version,
                                 &dissect_kafka_write_txn_markers_response_marker, NULL);

    proto_item_set_end(subti, tvb, offset);

    return offset;
}

/* TXN_OFFSET_COMMIT REQUEST/RESPONSE */

static int
dissect_kafka_txn_offset_commit_request_partition(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                                                     int offset, kafka_api_version_t api_version)
{
    uint32_t partition_id;
    int64_t partition_offset;
    proto_item *subti;
    proto_tree *subtree;

    subtree = proto_tree_add_subtree(tree, tvb, offset, -1, ett_kafka_partition, &subti, "Partition");

    partition_id = tvb_get_ntohl(tvb, offset);
    proto_tree_add_item(subtree, hf_kafka_partition_id, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;

    partition_offset = tvb_get_ntohi64(tvb, offset);
    proto_tree_add_item(subtree, hf_kafka_offset, tvb, offset, 8, ENC_BIG_ENDIAN);
    offset += 8;

    if (api_version >= 2) {
        proto_tree_add_item(subtree, hf_kafka_leader_epoch, tvb, offset, 4, ENC_BIG_ENDIAN);
        offset += 4;
    }

    offset = dissect_kafka_string(subtree, hf_kafka_metadata, tvb, pinfo, offset, api_version >= 3, NULL, NULL);

    if (api_version >= 3) {
        offset = dissect_kafka_tagged_fields(tvb, pinfo, subtree, offset, 0);
    }

    proto_item_set_end(subti, tvb, offset);

    proto_item_append_text(subti, " (ID=%u, Offset=%" PRIi64 ")", partition_id, partition_offset);

    return offset;
}

static int
dissect_kafka_txn_offset_commit_request_topic(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                                           int offset, kafka_api_version_t api_version)
{
    int topic_start, topic_len;
    proto_item *subti, *subsubti;
    proto_tree *subtree, *subsubtree;

    subtree = proto_tree_add_subtree(tree, tvb, offset, -1, ett_kafka_topic, &subti, "Topic");

    offset = dissect_kafka_string(subtree, hf_kafka_topic_name, tvb, pinfo, offset, api_version >= 3, &topic_start, &topic_len);

    subsubtree = proto_tree_add_subtree(subtree, tvb, offset, -1, ett_kafka_partitions, &subsubti, "Partitions");
    offset = dissect_kafka_array(subsubtree, tvb, pinfo, offset, api_version >= 3, api_version,
                                 &dissect_kafka_txn_offset_commit_request_partition, NULL);
    proto_item_set_end(subsubti, tvb, offset);


    if (api_version >= 3) {
        offset = dissect_kafka_tagged_fields(tvb, pinfo, subtree, offset, 0);
    }

    proto_item_set_end(subti, tvb, offset);
    proto_item_append_text(subti, " (Topic=%s)",
                           tvb_get_string_enc(pinfo->pool, tvb,
                                              topic_start, topic_len, ENC_UTF_8));

    return offset;
}

static int
dissect_kafka_txn_offset_commit_request(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset,
                                     kafka_api_version_t api_version)
{
    proto_item *subti;
    proto_tree *subtree;

    offset = dissect_kafka_string(tree, hf_kafka_transactional_id, tvb, pinfo, offset, api_version >= 3, NULL, NULL);

    offset = dissect_kafka_string(tree, hf_kafka_consumer_group, tvb, pinfo, offset, api_version >= 3, NULL, NULL);

    proto_tree_add_item(tree, hf_kafka_producer_id, tvb, offset, 8, ENC_BIG_ENDIAN);
    offset += 8;

    proto_tree_add_item(tree, hf_kafka_producer_epoch, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    if (api_version >= 3) {
        proto_tree_add_item(tree, hf_kafka_generation_id, tvb, offset, 4, ENC_BIG_ENDIAN);
        offset += 4;
    }

    if (api_version >= 3) {
        offset = dissect_kafka_string(tree, hf_kafka_member_id, tvb, pinfo, offset, 1,NULL, NULL);
    }

    if (api_version >= 3) {
        offset = dissect_kafka_string(tree, hf_kafka_consumer_group_instance, tvb, pinfo, offset, 1,NULL, NULL);
    }

    subtree = proto_tree_add_subtree(tree, tvb, offset, -1,
                                     ett_kafka_topics,
                                     &subti, "Topics");
    offset = dissect_kafka_array(subtree, tvb, pinfo, offset, api_version >= 3, api_version,
                                 &dissect_kafka_txn_offset_commit_request_topic, NULL);
    proto_item_set_end(subti, tvb, offset);

    if (api_version >= 3) {
        offset = dissect_kafka_tagged_fields(tvb, pinfo, tree, offset, 0);
    }

    return offset;
}

static int
dissect_kafka_txn_offset_commit_response_partition(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                                                      int offset, kafka_api_version_t api_version)
{
    uint32_t partition_id;
    kafka_error_t partition_error_code;

    proto_item *subti;
    proto_tree *subtree;

    subtree = proto_tree_add_subtree(tree, tvb, offset, -1, ett_kafka_partition, &subti, "Partition");

    partition_id = tvb_get_ntohl(tvb, offset);
    proto_tree_add_item(subtree, hf_kafka_partition_id, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;

    partition_error_code = (kafka_error_t) tvb_get_ntohs(tvb, offset);
    proto_tree_add_item(subtree, hf_kafka_error, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    if (api_version >= 3) {
        offset = dissect_kafka_tagged_fields(tvb, pinfo, subtree, offset, 0);
    }

    proto_item_set_end(subti, tvb, offset);

    if (partition_error_code == 0) {
        proto_item_append_text(subti, " (ID=%u)", partition_id);
    } else {
        proto_item_append_text(subti, " (ID=%u, Error=%s)", partition_id, kafka_error_to_str(partition_error_code));
    }

    return offset;
}

static int
dissect_kafka_txn_offset_commit_response_topic(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                                            int offset, kafka_api_version_t api_version)
{
    int topic_start, topic_len;
    proto_item *subti, *subsubti;
    proto_tree *subtree, *subsubtree;

    subtree = proto_tree_add_subtree(tree, tvb, offset, -1, ett_kafka_topic, &subti, "Topic");

    offset = dissect_kafka_string(subtree, hf_kafka_topic_name, tvb, pinfo, offset, api_version >= 3, &topic_start, &topic_len);

    subsubtree = proto_tree_add_subtree(subtree, tvb, offset, -1, ett_kafka_partitions, &subsubti, "Partitions");
    offset = dissect_kafka_array(subsubtree, tvb, pinfo, offset, api_version >= 3, api_version,
                                 &dissect_kafka_txn_offset_commit_response_partition, NULL);
    proto_item_set_end(subsubti, tvb, offset);

    if (api_version >= 3) {
        offset = dissect_kafka_tagged_fields(tvb, pinfo, subtree, offset, 0);
    }

    proto_item_set_end(subti, tvb, offset);
    proto_item_append_text(subti, " (Topic=%s)",
                           tvb_get_string_enc(pinfo->pool, tvb,
                                              topic_start, topic_len, ENC_UTF_8));

    return offset;
}


static int
dissect_kafka_txn_offset_commit_response(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset,
                                      kafka_api_version_t api_version)
{
    proto_item *subti;
    proto_tree *subtree;

    offset = dissect_kafka_throttle_time(tvb, pinfo, tree, offset);

    /* [topic_error_code] */
    subtree = proto_tree_add_subtree(tree, tvb, offset, -1,
                                     ett_kafka_topics,
                                     &subti, "Topics");
    offset = dissect_kafka_array(subtree, tvb, pinfo, offset, api_version >= 3, api_version,
                                 &dissect_kafka_txn_offset_commit_response_topic, NULL);
    proto_item_set_end(subti, tvb, offset);

    if (api_version >= 3) {
        offset = dissect_kafka_tagged_fields(tvb, pinfo, tree, offset, 0);
    }

    return offset;
}

/* DESCRIBE_ACLS REQUEST/RESPONSE */

static int
dissect_kafka_describe_acls_request(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset,
                                        kafka_api_version_t api_version)
{

    offset = dissect_kafka_int8(tree, hf_kafka_acl_resource_type, tvb, pinfo, offset, NULL);

    offset = dissect_kafka_string(tree, hf_kafka_acl_resource_name, tvb, pinfo, offset, api_version >= 2, NULL, NULL);

    if (api_version >= 1) {
        offset = dissect_kafka_int8(tree, hf_kafka_acl_resource_pattern_type, tvb, pinfo, offset, NULL);
    }

    offset = dissect_kafka_string(tree, hf_kafka_acl_principal, tvb, pinfo, offset, api_version >= 2, NULL, NULL);

    offset = dissect_kafka_string(tree, hf_kafka_acl_host, tvb, pinfo, offset, api_version >= 2, NULL, NULL);

    offset = dissect_kafka_int8(tree, hf_kafka_acl_operation, tvb, pinfo, offset, NULL);

    offset = dissect_kafka_int8(tree, hf_kafka_acl_permission_type, tvb, pinfo, offset, NULL);

    if (api_version >= 2) {
        offset = dissect_kafka_tagged_fields(tvb, pinfo, tree, offset, 0);
    }

    return offset;
}

static int
dissect_kafka_describe_acls_response_resource_acl(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                                                   int offset, kafka_api_version_t api_version)
{
    proto_item *subti;
    proto_tree *subtree;

    subtree = proto_tree_add_subtree(tree, tvb, offset, -1, ett_kafka_acl, &subti, "ACL");

    offset = dissect_kafka_string(subtree, hf_kafka_acl_principal, tvb, pinfo, offset, api_version >= 2, NULL, NULL);

    offset = dissect_kafka_string(subtree, hf_kafka_acl_host, tvb, pinfo, offset, api_version >= 2, NULL, NULL);

    offset = dissect_kafka_int8(subtree, hf_kafka_acl_operation, tvb, pinfo, offset, NULL);

    offset = dissect_kafka_int8(subtree, hf_kafka_acl_permission_type, tvb, pinfo, offset, NULL);

    if (api_version >= 2) {
        offset = dissect_kafka_tagged_fields(tvb, pinfo, subtree, offset, 0);
    }

    return offset;
}

static int
dissect_kafka_describe_acls_response_resource(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                                               int offset, kafka_api_version_t api_version)
{
    proto_item *subti, *subsubti;
    proto_tree *subtree, *subsubtree;

    subtree = proto_tree_add_subtree(tree, tvb, offset, -1, ett_kafka_resource, &subti, "Resource");

    offset = dissect_kafka_int8(subtree, hf_kafka_acl_resource_type, tvb, pinfo, offset, NULL);

    offset = dissect_kafka_string(subtree, hf_kafka_acl_resource_name, tvb, pinfo, offset, api_version >= 2, NULL, NULL);

    if (api_version >= 1) {
        offset = dissect_kafka_int8(subtree, hf_kafka_acl_resource_pattern_type, tvb, pinfo, offset, NULL);
    }

    subsubtree = proto_tree_add_subtree(subtree, tvb, offset, -1, ett_kafka_acls, &subsubti, "ACLs");
    offset = dissect_kafka_array(subsubtree, tvb, pinfo, offset, api_version >= 2, api_version,
                                 &dissect_kafka_describe_acls_response_resource_acl, NULL);
    proto_item_set_end(subsubti, tvb, offset);

    if (api_version >= 2) {
        offset = dissect_kafka_tagged_fields(tvb, pinfo, subtree, offset, 0);
    }

    proto_item_set_end(subti, tvb, offset);

    return offset;
}


static int
dissect_kafka_describe_acls_response(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset,
                                         kafka_api_version_t api_version)
{
    proto_item *subti;
    proto_tree *subtree;

    offset = dissect_kafka_throttle_time(tvb, pinfo, tree, offset);

    offset = dissect_kafka_error(tvb, pinfo, tree, offset);

    offset = dissect_kafka_string(tree, hf_kafka_error_message, tvb, pinfo, offset, api_version >= 2, NULL, NULL);

    subtree = proto_tree_add_subtree(tree, tvb, offset, -1,
                                     ett_kafka_resources,
                                     &subti, "Resources");
    offset = dissect_kafka_array(subtree, tvb, pinfo, offset, api_version >= 2, api_version,
                                 &dissect_kafka_describe_acls_response_resource, NULL);

    if (api_version >= 2) {
        offset = dissect_kafka_tagged_fields(tvb, pinfo, tree, offset, 0);
    }

    proto_item_set_end(subti, tvb, offset);

    return offset;
}

/* CREATE_ACLS REQUEST/RESPONSE */

static int
dissect_kafka_create_acls_request_creation(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree,
                                                  int offset, kafka_api_version_t api_version _U_)
{
    proto_item *subti;
    proto_tree *subtree;

    subtree = proto_tree_add_subtree(tree, tvb, offset, -1, ett_kafka_acl_creation, &subti, "Creation");

    offset = dissect_kafka_int8(subtree, hf_kafka_acl_resource_type, tvb, pinfo, offset, NULL);

    offset = dissect_kafka_string(subtree, hf_kafka_acl_resource_name, tvb, pinfo, offset, api_version >= 2, NULL, NULL);

    if (api_version >= 1) {
        offset = dissect_kafka_int8(subtree, hf_kafka_acl_resource_pattern_type, tvb, pinfo, offset, NULL);
    }

    offset = dissect_kafka_string(subtree, hf_kafka_acl_principal, tvb, pinfo, offset, api_version >= 2, NULL, NULL);

    offset = dissect_kafka_string(subtree, hf_kafka_acl_host, tvb, pinfo, offset, api_version >= 2, NULL, NULL);

    offset = dissect_kafka_int8(subtree, hf_kafka_acl_operation, tvb, pinfo, offset, NULL);

    offset = dissect_kafka_int8(subtree, hf_kafka_acl_permission_type, tvb, pinfo, offset, NULL);

    if (api_version >= 2) {
        offset = dissect_kafka_tagged_fields(tvb, pinfo, subtree, offset, 0);
    }

    proto_item_set_end(subti, tvb, offset);

    return offset;
}

static int
dissect_kafka_create_acls_request(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset,
                                        kafka_api_version_t api_version)
{
    proto_item *subti;
    proto_tree *subtree;

    subtree = proto_tree_add_subtree(tree, tvb, offset, -1,
                                     ett_kafka_acl_creations,
                                     &subti, "Creations");
    offset = dissect_kafka_array(subtree, tvb, pinfo, offset, api_version >= 2 , api_version,
                                 &dissect_kafka_create_acls_request_creation, NULL);
    proto_item_set_end(subti, tvb, offset);

    if (api_version >= 2) {
        offset = dissect_kafka_tagged_fields(tvb, pinfo, tree, offset, 0);
    }

    return offset;
}

static int
dissect_kafka_create_acls_response_creation(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree,
                                                   int offset, kafka_api_version_t api_version _U_)
{
    proto_item *subti;
    proto_tree *subtree;

    subtree = proto_tree_add_subtree(tree, tvb, offset, -1, ett_kafka_acl_creation, &subti, "Creation");

    offset = dissect_kafka_error(tvb, pinfo, subtree, offset);

    offset = dissect_kafka_string(subtree, hf_kafka_error_message, tvb, pinfo, offset, api_version >= 2, NULL, NULL);

    if (api_version >= 2) {
        offset = dissect_kafka_tagged_fields(tvb, pinfo, subtree, offset, 0);
    }

    proto_item_set_end(subti, tvb, offset);

    return offset;
}

static int
dissect_kafka_create_acls_response(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset,
                                         kafka_api_version_t api_version)
{
    proto_item *subti;
    proto_tree *subtree;

    offset = dissect_kafka_throttle_time(tvb, pinfo, tree, offset);

    subtree = proto_tree_add_subtree(tree, tvb, offset, -1,
                                     ett_kafka_acl_creations,
                                     &subti, "Creations");
    offset = dissect_kafka_array(subtree, tvb, pinfo, offset, api_version >= 2, api_version,
                                 &dissect_kafka_create_acls_response_creation, NULL);
    proto_item_set_end(subti, tvb, offset);

    if (api_version >= 2) {
        offset = dissect_kafka_tagged_fields(tvb, pinfo, tree, offset, 0);
    }

    return offset;
}

/* DELETE_ACLS REQUEST/RESPONSE */

static int
dissect_kafka_delete_acls_request_filter(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree,
                                           int offset, kafka_api_version_t api_version _U_)
{
    proto_item *subti;
    proto_tree *subtree;

    subtree = proto_tree_add_subtree(tree, tvb, offset, -1, ett_kafka_acl_filter, &subti, "Filter");

    offset = dissect_kafka_int8(subtree, hf_kafka_acl_resource_type, tvb, pinfo, offset, NULL);

    offset = dissect_kafka_string(subtree, hf_kafka_acl_resource_name, tvb, pinfo, offset, api_version >= 2, NULL, NULL);

    if (api_version >= 1) {
        offset = dissect_kafka_int8(subtree, hf_kafka_acl_resource_pattern_type, tvb, pinfo, offset, NULL);
    }

    offset = dissect_kafka_string(subtree, hf_kafka_acl_principal, tvb, pinfo, offset, api_version >= 2, NULL, NULL);

    offset = dissect_kafka_string(subtree, hf_kafka_acl_host, tvb, pinfo, offset, api_version >= 2, NULL, NULL);

    offset = dissect_kafka_int8(subtree, hf_kafka_acl_operation, tvb, pinfo, offset, NULL);

    offset = dissect_kafka_int8(subtree, hf_kafka_acl_permission_type, tvb, pinfo, offset, NULL);

    if (api_version >= 2) {
        offset = dissect_kafka_tagged_fields(tvb, pinfo, subtree, offset, 0);
    }

    proto_item_set_end(subti, tvb, offset);

    return offset;
}

static int
dissect_kafka_delete_acls_request(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset,
                                  kafka_api_version_t api_version)
{
    proto_item *subti;
    proto_tree *subtree;

    subtree = proto_tree_add_subtree(tree, tvb, offset, -1,
                                     ett_kafka_acl_filter,
                                     &subti, "Filters");
    offset = dissect_kafka_array(subtree, tvb, pinfo, offset, api_version >= 2, api_version,
                                 &dissect_kafka_delete_acls_request_filter, NULL);
    proto_item_set_end(subti, tvb, offset);

    if (api_version >= 2) {
        offset = dissect_kafka_tagged_fields(tvb, pinfo, tree, offset, 0);
    }

    return offset;
}

static int
dissect_kafka_delete_acls_response_match(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree,
                                          int offset, kafka_api_version_t api_version _U_)
{
    proto_item *subti;
    proto_tree *subtree;

    subtree = proto_tree_add_subtree(tree, tvb, offset, -1, ett_kafka_acl_filter_match, &subti, "Match");

    offset = dissect_kafka_error(tvb, pinfo, subtree, offset);

    offset = dissect_kafka_string(subtree, hf_kafka_error_message, tvb, pinfo, offset, api_version >= 2, NULL, NULL);

    offset = dissect_kafka_int8(subtree, hf_kafka_acl_resource_type, tvb, pinfo, offset, NULL);

    offset = dissect_kafka_string(subtree, hf_kafka_acl_resource_name, tvb, pinfo, offset, api_version >= 2, NULL, NULL);

    if (api_version >= 1) {
        offset = dissect_kafka_int8(subtree, hf_kafka_acl_resource_pattern_type, tvb, pinfo, offset, NULL);
    }

    offset = dissect_kafka_string(subtree, hf_kafka_acl_principal, tvb, pinfo, offset, api_version >= 2, NULL, NULL);

    offset = dissect_kafka_string(subtree, hf_kafka_acl_host, tvb, pinfo, offset, api_version >= 2, NULL, NULL);

    offset = dissect_kafka_int8(subtree, hf_kafka_acl_operation, tvb, pinfo, offset, NULL);

    offset = dissect_kafka_int8(subtree, hf_kafka_acl_permission_type, tvb, pinfo, offset, NULL);

    if (api_version >= 2) {
        offset = dissect_kafka_tagged_fields(tvb, pinfo, subtree, offset, 0);
    }

    proto_item_set_end(subti, tvb, offset);

    return offset;
}

static int
dissect_kafka_delete_acls_response_filter(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree,
                                            int offset, kafka_api_version_t api_version _U_)
{
    proto_item *subti, *subsubti;
    proto_tree *subtree, *subsubtree;

    subtree = proto_tree_add_subtree(tree, tvb, offset, -1, ett_kafka_acl_creation, &subti, "Filter");

    offset = dissect_kafka_error(tvb, pinfo, subtree, offset);

    offset = dissect_kafka_string(subtree, hf_kafka_error_message, tvb, pinfo, offset, api_version >= 2, NULL, NULL);

    subsubtree = proto_tree_add_subtree(subtree, tvb, offset, -1,
                                     ett_kafka_acl_filter_matches,
                                     &subsubti, "Matches");
    offset = dissect_kafka_array(subsubtree, tvb, pinfo, offset, api_version >= 2, api_version,
                                 &dissect_kafka_delete_acls_response_match, NULL);

    proto_item_set_end(subsubti, tvb, offset);

    if (api_version >= 2) {
        offset = dissect_kafka_tagged_fields(tvb, pinfo, subtree, offset, 0);
    }

    proto_item_set_end(subti, tvb, offset);

    return offset;
}

static int
dissect_kafka_delete_acls_response(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset,
                                   kafka_api_version_t api_version)
{
    proto_item *subti;
    proto_tree *subtree;

    offset = dissect_kafka_throttle_time(tvb, pinfo, tree, offset);

    subtree = proto_tree_add_subtree(tree, tvb, offset, -1,
                                     ett_kafka_acl_creations,
                                     &subti, "Filters");
    offset = dissect_kafka_array(subtree, tvb, pinfo, offset, api_version >= 0, api_version,
                                 &dissect_kafka_delete_acls_response_filter, NULL);
    proto_item_set_end(subti, tvb, offset);

    if (api_version >= 2) {
        offset = dissect_kafka_tagged_fields(tvb, pinfo, tree, offset, 0);
    }

    return offset;
}

/* DESCRIBE_CONFIGS REQUEST/RESPONSE */

static int
dissect_kafka_describe_config_request_entry(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                                               int offset, kafka_api_version_t api_version _U_)
{
    offset = dissect_kafka_string(tree, hf_kafka_config_key, tvb, pinfo, offset, api_version >= 4, NULL, NULL);

    return offset;
}

static int
dissect_kafka_describe_config_request_resource(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                                         int offset, kafka_api_version_t api_version)
{
    proto_item *subti, *subsubti;
    proto_tree *subtree, *subsubtree;

    subtree = proto_tree_add_subtree(tree, tvb, offset, -1, ett_kafka_resource, &subti, "Resource");

    proto_tree_add_item(subtree, hf_kafka_config_resource_type, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;

    offset = dissect_kafka_string(subtree, hf_kafka_config_resource_name, tvb, pinfo, offset, api_version >= 4, NULL, NULL);

    subsubtree = proto_tree_add_subtree(subtree, tvb, offset, -1, ett_kafka_config_entries, &subsubti, "Entries");

    offset = dissect_kafka_array(subsubtree, tvb, pinfo, offset, api_version >= 4, api_version,
                                 &dissect_kafka_describe_config_request_entry, NULL);

    if (api_version >= 4) {
        offset = dissect_kafka_tagged_fields(tvb, pinfo, subtree, offset, 0);
    }

    proto_item_set_end(subti, tvb, offset);

    return offset;
}

static int
dissect_kafka_describe_configs_request(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset,
                                  kafka_api_version_t api_version)
{
    proto_item *subti;
    proto_tree *subtree;

    subtree = proto_tree_add_subtree(tree, tvb, offset, -1,
                                     ett_kafka_resources,
                                     &subti, "Resources");
    offset = dissect_kafka_array(subtree, tvb, pinfo, offset, api_version >= 4, api_version,
                                 &dissect_kafka_describe_config_request_resource, NULL);

    proto_item_set_end(subti, tvb, offset);

    if (api_version >= 1) {
        proto_tree_add_item(tree, hf_kafka_config_include_synonyms, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset += 1;
    }

    if (api_version >= 3) {
        offset = dissect_kafka_bool(tree, hf_kafka_config_include_documentation, tvb, pinfo, offset);
    }

    if (api_version >= 4) {
        offset = dissect_kafka_tagged_fields(tvb, pinfo, tree, offset, 0);
    }

    return offset;
}

static int
dissect_kafka_describe_configs_response_synonym(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                                              int offset, kafka_api_version_t api_version _U_)
{
    proto_item *subti;
    proto_tree *subtree;
    int key_start, key_len;

    subtree = proto_tree_add_subtree(tree, tvb, offset, -1, ett_kafka_config_synonym, &subti, "Synonym");

    offset = dissect_kafka_string(subtree, hf_kafka_config_key, tvb, pinfo, offset, 0, &key_start, &key_len);
    offset = dissect_kafka_string(subtree, hf_kafka_config_value, tvb, pinfo, offset, 0, NULL, NULL);

    proto_tree_add_item(subtree, hf_kafka_config_source, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;

    if (api_version >= 4) {
        offset = dissect_kafka_tagged_fields(tvb, pinfo, subtree, offset, 0);
    }

    proto_item_set_end(subti, tvb, offset);
    proto_item_append_text(subti, " (Key=%s)",
                           tvb_get_string_enc(pinfo->pool, tvb,
                                              key_start, key_len, ENC_UTF_8));

    return offset;
}

static int
dissect_kafka_describe_configs_response_entry(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                                         int offset, kafka_api_version_t api_version _U_)
{
    proto_item *subti, *subsubti;
    proto_tree *subtree, *subsubtree;
    int key_start, key_len;

    subtree = proto_tree_add_subtree(tree, tvb, offset, -1, ett_kafka_config_entry, &subti, "Entry");

    offset = dissect_kafka_string(subtree, hf_kafka_config_key, tvb, pinfo, offset, api_version >= 4, &key_start, &key_len);
    offset = dissect_kafka_string(subtree, hf_kafka_config_value, tvb, pinfo, offset, api_version >= 4, NULL, NULL);

    proto_tree_add_item(subtree, hf_kafka_config_readonly, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;

    if (api_version == 0) {
        proto_tree_add_item(subtree, hf_kafka_config_default, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset += 1;
    } else {
        proto_tree_add_item(subtree, hf_kafka_config_source, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset += 1;
    }

    proto_tree_add_item(subtree, hf_kafka_config_sensitive, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;

    if (api_version >= 1) {
        subsubtree = proto_tree_add_subtree(subtree, tvb, offset, -1,
                                            ett_kafka_config_synonyms,
                                            &subsubti, "Synonyms");
        offset = dissect_kafka_array(subsubtree, tvb, pinfo, offset, api_version >= 4, api_version,
                                     &dissect_kafka_describe_configs_response_synonym, NULL);

        proto_item_set_end(subsubti, tvb, offset);
    }

    if (api_version >= 3) {
        offset = dissect_kafka_int8(subtree, hf_kafka_config_data_type, tvb, pinfo, offset, NULL);

        offset = dissect_kafka_string(subtree, hf_kafka_config_documentation, tvb, pinfo, offset, api_version >= 4, NULL, NULL);
    }

    if (api_version >= 4) {
        offset = dissect_kafka_tagged_fields(tvb, pinfo, subtree, offset, 0);
    }

    proto_item_set_end(subti, tvb, offset);
    proto_item_append_text(subti, " (Key=%s)",
                           tvb_get_string_enc(pinfo->pool, tvb,
                                              key_start, key_len, ENC_UTF_8));

    return offset;
}

static int
dissect_kafka_describe_configs_response_resource(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree,
                                          int offset, kafka_api_version_t api_version _U_)
{
    proto_item *subti, *subsubti;
    proto_tree *subtree, *subsubtree;

    subtree = proto_tree_add_subtree(tree, tvb, offset, -1, ett_kafka_resource, &subti, "Resource");

    offset = dissect_kafka_error(tvb, pinfo, subtree, offset);

    offset = dissect_kafka_string(subtree, hf_kafka_error_message, tvb, pinfo, offset, api_version >= 4, NULL, NULL);

    proto_tree_add_item(subtree, hf_kafka_config_resource_type, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;

    offset = dissect_kafka_string(subtree, hf_kafka_config_resource_name, tvb, pinfo, offset, api_version >= 4, NULL, NULL);

    subsubtree = proto_tree_add_subtree(subtree, tvb, offset, -1,
                                        ett_kafka_config_entries,
                                        &subsubti, "Entries");
    offset = dissect_kafka_array(subsubtree, tvb, pinfo, offset, api_version >= 4, api_version,
                                 &dissect_kafka_describe_configs_response_entry, NULL);

    proto_item_set_end(subsubti, tvb, offset);

    if (api_version >= 4) {
        offset = dissect_kafka_tagged_fields(tvb, pinfo, subtree, offset, 0);
    }

    proto_item_set_end(subti, tvb, offset);

    return offset;
}

static int
dissect_kafka_describe_configs_response(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset,
                                   kafka_api_version_t api_version)
{
    proto_item *subti;
    proto_tree *subtree;

    offset = dissect_kafka_throttle_time(tvb, pinfo, tree, offset);

    subtree = proto_tree_add_subtree(tree, tvb, offset, -1,
                                     ett_kafka_resources,
                                     &subti, "Resources");
    offset = dissect_kafka_array(subtree, tvb, pinfo, offset, api_version >= 4, api_version,
                                 &dissect_kafka_describe_configs_response_resource, NULL);

    proto_item_set_end(subti, tvb, offset);

    if (api_version >= 4) {
        offset = dissect_kafka_tagged_fields(tvb, pinfo, tree, offset, 0);
    }

    return offset;
}

/* ALTER_CONFIGS REQUEST/RESPONSE */

static int
dissect_kafka_alter_config_request_entry(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree,
                                            int offset, kafka_api_version_t api_version _U_)
{
    proto_item *subti;
    proto_tree *subtree;

    subtree = proto_tree_add_subtree(tree, tvb, offset, -1, ett_kafka_config_entry, &subti, "Entry");

    offset = dissect_kafka_string(subtree, hf_kafka_config_key, tvb, pinfo, offset, 0, NULL, NULL);
    offset = dissect_kafka_string(subtree, hf_kafka_config_value, tvb, pinfo, offset, 0, NULL, NULL);

    proto_item_set_end(subti, tvb, offset);

    return offset;
}

static int
dissect_kafka_alter_config_request_resource(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree,
                                               int offset, kafka_api_version_t api_version _U_)
{
    proto_item *subti, *subsubti;
    proto_tree *subtree, *subsubtree;

    subtree = proto_tree_add_subtree(tree, tvb, offset, -1, ett_kafka_resource, &subti, "Resource");

    proto_tree_add_item(subtree, hf_kafka_config_resource_type, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;

    offset = dissect_kafka_string(subtree, hf_kafka_config_resource_name, tvb, pinfo, offset, 0, NULL, NULL);

    subsubtree = proto_tree_add_subtree(tree, tvb, offset, -1, ett_kafka_config_entries, &subsubti, "Entries");

    offset = dissect_kafka_array(subsubtree, tvb, pinfo, offset, 0, api_version,
                                 &dissect_kafka_alter_config_request_entry, NULL);

    proto_item_set_end(subti, tvb, offset);

    return offset;
}

static int
dissect_kafka_alter_configs_request(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset,
                                       kafka_api_version_t api_version)
{
    proto_item *subti;
    proto_tree *subtree;

    subtree = proto_tree_add_subtree(tree, tvb, offset, -1,
                                     ett_kafka_resources,
                                     &subti, "Resources");
    offset = dissect_kafka_array(subtree, tvb, pinfo, offset, 0, api_version,
                                 &dissect_kafka_alter_config_request_resource, NULL);

    proto_tree_add_item(subtree, hf_kafka_validate_only, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;

    proto_item_set_end(subti, tvb, offset);

    return offset;
}

static int
dissect_kafka_alter_configs_response_resource(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree,
                                                 int offset, kafka_api_version_t api_version _U_)
{
    proto_item *subti;
    proto_tree *subtree;

    subtree = proto_tree_add_subtree(tree, tvb, offset, -1, ett_kafka_resource, &subti, "Resource");

    offset = dissect_kafka_error(tvb, pinfo, subtree, offset);

    offset = dissect_kafka_string(subtree, hf_kafka_error_message, tvb, pinfo, offset, 0, NULL, NULL);

    proto_tree_add_item(subtree, hf_kafka_config_resource_type, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;

    offset = dissect_kafka_string(subtree, hf_kafka_config_resource_name, tvb, pinfo, offset, 0, NULL, NULL);

    proto_item_set_end(subti, tvb, offset);

    return offset;
}

static int
dissect_kafka_alter_configs_response(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset,
                                        kafka_api_version_t api_version)
{
    proto_item *subti;
    proto_tree *subtree;

    offset = dissect_kafka_throttle_time(tvb, pinfo, tree, offset);

    subtree = proto_tree_add_subtree(tree, tvb, offset, -1,
                                     ett_kafka_resources,
                                     &subti, "Resources");
    offset = dissect_kafka_array(subtree, tvb, pinfo, offset, 0, api_version,
                                 &dissect_kafka_alter_configs_response_resource, NULL);

    proto_item_set_end(subti, tvb, offset);

    return offset;
}

/* ALTER_REPLICA_LOG_DIRS REQUEST/RESPONSE */

static int
dissect_kafka_alter_replica_log_dirs_request_partition(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree,
                                         int offset, kafka_api_version_t api_version _U_)
{
    proto_tree_add_item(tree, hf_kafka_partition_id, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;

    return offset;
}

static int
dissect_kafka_alter_replica_log_dirs_request_topic(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                                                 int offset, kafka_api_version_t api_version _U_)
{
    proto_item *subti, *subsubti;
    proto_tree *subtree, *subsubtree;
    int topic_start, topic_len;

    subtree = proto_tree_add_subtree(tree, tvb, offset, -1, ett_kafka_resource, &subti, "Topic");

    offset = dissect_kafka_string(subtree, hf_kafka_topic_name, tvb, pinfo, offset, 0, &topic_start, &topic_len);

    subsubtree = proto_tree_add_subtree(tree, tvb, offset, -1, ett_kafka_topics, &subsubti, "Partitions");

    offset = dissect_kafka_array(subsubtree, tvb, pinfo, offset, 0, api_version,
                                 &dissect_kafka_alter_replica_log_dirs_request_partition, NULL);

    proto_item_set_end(subti, tvb, offset);
    proto_item_append_text(subti, " (Name=%s)",
                           tvb_get_string_enc(pinfo->pool, tvb,
                                              topic_start, topic_len, ENC_UTF_8));

    return offset;
}

static int
dissect_kafka_alter_replica_log_dirs_request_log_dir(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                                            int offset, kafka_api_version_t api_version)
{
    proto_item *subti, *subsubti;
    proto_tree *subtree, *subsubtree;

    subtree = proto_tree_add_subtree(tree, tvb, offset, -1, ett_kafka_log_dir, &subti, "Log Directory");

    offset = dissect_kafka_string(subtree, hf_kafka_log_dir, tvb, pinfo, offset, 0, NULL, NULL);

    subsubtree = proto_tree_add_subtree(tree, tvb, offset, -1, ett_kafka_topics, &subsubti, "Topics");

    offset = dissect_kafka_array(subsubtree, tvb, pinfo, offset, 0, api_version,
                                 &dissect_kafka_alter_replica_log_dirs_request_topic, NULL);

    proto_item_set_end(subti, tvb, offset);

    return offset;
}

static int
dissect_kafka_alter_replica_log_dirs_request(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset,
                                    kafka_api_version_t api_version)
{
    proto_item *subti;
    proto_tree *subtree;

    subtree = proto_tree_add_subtree(tree, tvb, offset, -1,
                                     ett_kafka_log_dirs,
                                     &subti, "Log Directories");
    offset = dissect_kafka_array(subtree, tvb, pinfo, offset, 0, api_version,
                                 &dissect_kafka_alter_replica_log_dirs_request_log_dir, NULL);

    proto_item_set_end(subti, tvb, offset);

    return offset;
}

static int
dissect_kafka_alter_replica_log_dirs_response_partition(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree,
                                       int offset, kafka_api_version_t api_version _U_)
{
    proto_item *subti;
    proto_tree *subtree;
    int partition_id;

    subtree = proto_tree_add_subtree(tree, tvb, offset, -1, ett_kafka_partition, &subti, "Partition");

    partition_id = tvb_get_ntohl(tvb, offset);
    proto_tree_add_item(subtree, hf_kafka_partition_id, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;

    offset = dissect_kafka_error(tvb, pinfo, subtree, offset);

    proto_item_append_text(subti, " (ID=%u)", partition_id);

    proto_item_set_end(subti, tvb, offset);

    return offset;
}

static int
dissect_kafka_alter_replica_log_dirs_response_topic(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree,
                                              int offset, kafka_api_version_t api_version)
{
    proto_item *subti, *subsubti;
    proto_tree *subtree, *subsubtree;
    int topic_start, topic_len;

    subtree = proto_tree_add_subtree(tree, tvb, offset, -1, ett_kafka_topic, &subti, "Topic");

    offset = dissect_kafka_string(subtree, hf_kafka_log_dir, tvb, pinfo, offset, 0, &topic_start, &topic_len);

    subsubtree = proto_tree_add_subtree(tree, tvb, offset, -1, ett_kafka_partitions, &subsubti, "Partition");

    offset = dissect_kafka_array(subsubtree, tvb, pinfo, offset, 0, api_version,
                                 &dissect_kafka_alter_replica_log_dirs_response_partition, NULL);

    proto_item_set_end(subti, tvb, offset);
    proto_item_append_text(subti, " (Name=%s)",
                           tvb_get_string_enc(pinfo->pool, tvb,
                                              topic_start, topic_len, ENC_UTF_8));

    return offset;
}

static int
dissect_kafka_alter_replica_log_dirs_response(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset,
                                     kafka_api_version_t api_version)
{
    proto_item *subti;
    proto_tree *subtree;

    offset = dissect_kafka_throttle_time(tvb, pinfo, tree, offset);

    subtree = proto_tree_add_subtree(tree, tvb, offset, -1,
                                     ett_kafka_topics,
                                     &subti, "Topics");
    offset = dissect_kafka_array(subtree, tvb, pinfo, offset, 0, api_version,
                                 &dissect_kafka_alter_replica_log_dirs_response_topic, NULL);

    proto_item_set_end(subti, tvb, offset);

    return offset;
}

/* DESCRIBE_LOG_DIRS REQUEST/RESPONSE */

static int
dissect_kafka_describe_log_dirs_request_partition(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree,
                                                       int offset, kafka_api_version_t api_version _U_)
{
    proto_tree_add_item(tree, hf_kafka_partition_id, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;

    return offset;
}

static int
dissect_kafka_describe_log_dirs_request_topic(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                                                   int offset, kafka_api_version_t api_version _U_)
{
    proto_item *subti, *subsubti;
    proto_tree *subtree, *subsubtree;
    int topic_start, topic_len;

    subtree = proto_tree_add_subtree(tree, tvb, offset, -1, ett_kafka_resource, &subti, "Topic");

    offset = dissect_kafka_string(subtree, hf_kafka_topic_name, tvb, pinfo, offset, 0, &topic_start, &topic_len);

    subsubtree = proto_tree_add_subtree(tree, tvb, offset, -1, ett_kafka_partitions, &subsubti, "Partitions");

    offset = dissect_kafka_array(subsubtree, tvb, pinfo, offset, 0, api_version,
                                 &dissect_kafka_describe_log_dirs_request_partition, NULL);

    proto_item_set_end(subti, tvb, offset);
    proto_item_append_text(subti, " (Name=%s)",
                           tvb_get_string_enc(pinfo->pool, tvb,
                                              topic_start, topic_len, ENC_UTF_8));

    return offset;
}

static int
dissect_kafka_describe_log_dirs_request(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset,
                                             kafka_api_version_t api_version)
{
    proto_item *subti;
    proto_tree *subtree;

    subtree = proto_tree_add_subtree(tree, tvb, offset, -1,
                                     ett_kafka_topics,
                                     &subti, "Topics");
    offset = dissect_kafka_array(subtree, tvb, pinfo, offset, 0, api_version,
                                 &dissect_kafka_describe_log_dirs_request_topic, NULL);

    proto_item_set_end(subti, tvb, offset);

    return offset;
}

static int
dissect_kafka_describe_log_dirs_response_partition(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree,
                                                        int offset, kafka_api_version_t api_version _U_)
{
    proto_item *subti;
    proto_tree *subtree;

    int partition_id;

    subtree = proto_tree_add_subtree(tree, tvb, offset, -1, ett_kafka_partition, &subti, "Partition");

    partition_id = tvb_get_ntohl(tvb, offset);
    proto_tree_add_item(subtree, hf_kafka_partition_id, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;

    proto_tree_add_item(subtree, hf_kafka_segment_size, tvb, offset, 8, ENC_BIG_ENDIAN);
    offset += 8;

    proto_tree_add_item(subtree, hf_kafka_offset_lag, tvb, offset, 8, ENC_BIG_ENDIAN);
    offset += 8;

    proto_tree_add_item(subtree, hf_kafka_future, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;

    proto_item_set_end(subti, tvb, offset);
    proto_item_append_text(subti, " (ID=%u)", partition_id);

    return offset;
}

static int
dissect_kafka_describe_log_dirs_response_topic(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                                                    int offset, kafka_api_version_t api_version)
{
    proto_item *subti, *subsubti;
    proto_tree *subtree, *subsubtree;
    int topic_start, topic_len;

    subtree = proto_tree_add_subtree(tree, tvb, offset, -1, ett_kafka_topic, &subti, "Topic");

    offset = dissect_kafka_string(subtree, hf_kafka_topic_name, tvb, pinfo, offset, 0, &topic_start, &topic_len);

    subsubtree = proto_tree_add_subtree(subtree, tvb, offset, -1, ett_kafka_partitions, &subsubti, "Partitions");

    offset = dissect_kafka_array(subsubtree, tvb, pinfo, offset, 0, api_version,
                                 &dissect_kafka_describe_log_dirs_response_partition, NULL);

    proto_item_set_end(subti, tvb, offset);
    proto_item_append_text(subti, " (Name=%s)",
                           tvb_get_string_enc(pinfo->pool, tvb,
                                              topic_start, topic_len, ENC_UTF_8));

    return offset;
}

static int
dissect_kafka_describe_log_dirs_response_log_dir(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                                                    int offset, kafka_api_version_t api_version)
{
    proto_item *subti, *subsubti;
    proto_tree *subtree, *subsubtree;
    int dir_start, dir_len;

    subtree = proto_tree_add_subtree(tree, tvb, offset, -1, ett_kafka_log_dir, &subti, "Log Directory");

    offset = dissect_kafka_error(tvb, pinfo, subtree, offset);

    offset = dissect_kafka_string(subtree, hf_kafka_log_dir, tvb, pinfo, offset, 0, &dir_start, &dir_len);

    subsubtree = proto_tree_add_subtree(subtree, tvb, offset, -1, ett_kafka_topics, &subsubti, "Topics");

    offset = dissect_kafka_array(subsubtree, tvb, pinfo, offset, 0, api_version,
                                 &dissect_kafka_describe_log_dirs_response_topic, NULL);

    proto_item_set_end(subti, tvb, offset);
    proto_item_append_text(subti, " (Dir=%s)",
                           tvb_get_string_enc(pinfo->pool, tvb,
                                              dir_start, dir_len, ENC_UTF_8));

    return offset;
}

static int
dissect_kafka_describe_log_dirs_response(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset,
                                              kafka_api_version_t api_version)
{
    proto_item *subti;
    proto_tree *subtree;

    offset = dissect_kafka_throttle_time(tvb, pinfo, tree, offset);

    subtree = proto_tree_add_subtree(tree, tvb, offset, -1,
                                     ett_kafka_log_dirs,
                                     &subti, "Log Directories");
    offset = dissect_kafka_array(subtree, tvb, pinfo, offset, 0, api_version,
                                 &dissect_kafka_describe_log_dirs_response_log_dir, NULL);

    proto_item_set_end(subti, tvb, offset);

    return offset;
}

/* CREATE_PARTITIONS REQUEST/RESPONSE */

static int
dissect_kafka_create_partitions_request_broker(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree,
                                                  int offset, kafka_api_version_t api_version _U_)
{
    proto_tree_add_item(tree, hf_kafka_broker_nodeid, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;

    return offset;
}

static int
dissect_kafka_create_partitions_request_topic(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                                              int offset, kafka_api_version_t api_version)
{
    proto_item *subti, *subsubti;
    proto_tree *subtree, *subsubtree;
    int topic_start, topic_len;

    subtree = proto_tree_add_subtree(tree, tvb, offset, -1, ett_kafka_resource, &subti, "Topic");

    offset = dissect_kafka_string(subtree, hf_kafka_topic_name, tvb, pinfo, offset, api_version >= 2, &topic_start, &topic_len);

    proto_tree_add_item(subtree, hf_kafka_partition_count, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;

    subsubtree = proto_tree_add_subtree(subtree, tvb, offset, -1, ett_kafka_brokers, &subsubti, "Brokers");
    offset = dissect_kafka_array(subsubtree, tvb, pinfo, offset, api_version >= 2, api_version,
                                 &dissect_kafka_create_partitions_request_broker, NULL);
    proto_item_set_end(subsubti, tvb, offset);

    if (api_version >= 2) {
        offset = dissect_kafka_tagged_fields(tvb, pinfo, subtree, offset, 0);
    }

    proto_item_set_end(subti, tvb, offset);
    proto_item_append_text(subti, " (Name=%s)",
                           tvb_get_string_enc(pinfo->pool, tvb,
                                              topic_start, topic_len, ENC_UTF_8));

    return offset;
}

static int
dissect_kafka_create_partitions_request(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset,
                                        kafka_api_version_t api_version)
{
    proto_item *subti;
    proto_tree *subtree;

    subtree = proto_tree_add_subtree(tree, tvb, offset, -1,
                                     ett_kafka_topics,
                                     &subti, "Topics");
    offset = dissect_kafka_array(subtree, tvb, pinfo, offset, api_version >= 2, api_version,
                                 &dissect_kafka_create_partitions_request_topic, NULL);
    proto_item_set_end(subti, tvb, offset);

    proto_tree_add_item(tree, hf_kafka_timeout, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;

    proto_tree_add_item(tree, hf_kafka_validate_only, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;

    if (api_version >= 2) {
        offset = dissect_kafka_tagged_fields(tvb, pinfo, tree, offset, 0);
    }

    return offset;
}

static int
dissect_kafka_create_partitions_response_topic(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                                               int offset, kafka_api_version_t api_version)
{
    proto_item *subti;
    proto_tree *subtree;
    int topic_start, topic_len;

    subtree = proto_tree_add_subtree(tree, tvb, offset, -1, ett_kafka_topic, &subti, "Topic");

    offset = dissect_kafka_string(subtree, hf_kafka_topic_name, tvb, pinfo, offset, api_version >= 2, &topic_start, &topic_len);

    offset = dissect_kafka_error(tvb, pinfo, subtree, offset);

    offset = dissect_kafka_string(subtree, hf_kafka_error_message, tvb, pinfo, offset, api_version >= 2, NULL, NULL);

    if (api_version >= 2) {
        offset = dissect_kafka_tagged_fields(tvb, pinfo, subtree, offset, 0);
    }

    proto_item_set_end(subti, tvb, offset);
    proto_item_append_text(subti, " (Name=%s)",
                           tvb_get_string_enc(pinfo->pool, tvb,
                                              topic_start, topic_len, ENC_UTF_8));

    return offset;
}

static int
dissect_kafka_create_partitions_response(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset,
                                         kafka_api_version_t api_version)
{
    proto_item *subti;
    proto_tree *subtree;

    offset = dissect_kafka_throttle_time(tvb, pinfo, tree, offset);

    subtree = proto_tree_add_subtree(tree, tvb, offset, -1,
                                     ett_kafka_topics,
                                     &subti, "Topics");
    offset = dissect_kafka_array(subtree, tvb, pinfo, offset, api_version >= 2, api_version,
                                 &dissect_kafka_create_partitions_response_topic, NULL);
    proto_item_set_end(subti, tvb, offset);

    if (api_version >= 2) {
        offset = dissect_kafka_tagged_fields(tvb, pinfo, tree, offset, 0);
    }

    return offset;
}

/* SASL_AUTHENTICATE REQUEST/RESPONSE */

static int
dissect_kafka_sasl_authenticate_request(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset,
                                         kafka_api_version_t api_version)
{
    offset = dissect_kafka_bytes(tree, hf_kafka_sasl_auth_bytes, tvb, pinfo, offset, api_version >= 2, NULL, NULL);

    if (api_version >= 2) {
        offset = dissect_kafka_tagged_fields(tvb, pinfo, tree, offset, 0);
    }

    return offset;
}


static int
dissect_kafka_sasl_authenticate_response(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset,
                                          kafka_api_version_t api_version _U_)
{
    offset = dissect_kafka_error(tvb, pinfo, tree, offset);

    offset = dissect_kafka_string(tree, hf_kafka_error_message, tvb, pinfo, offset, api_version >= 2, NULL, NULL);

    offset = dissect_kafka_bytes(tree, hf_kafka_sasl_auth_bytes, tvb, pinfo, offset, api_version >= 2, NULL, NULL);

    if (api_version >= 1) {
        offset = dissect_kafka_int64(tree, hf_kafka_session_lifetime_ms, tvb, pinfo, offset, NULL);
    }

    if (api_version >= 2) {
        offset = dissect_kafka_tagged_fields(tvb, pinfo, tree, offset, 0);
    }

    return offset;
}

/* CREATE_DELEGATION_TOKEN REQUEST/RESPONSE */

static int
dissect_kafka_create_delegation_token_request_renewer(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                                              int offset, kafka_api_version_t api_version)
{
    proto_item *subti;
    proto_tree *subtree;

    subtree = proto_tree_add_subtree(tree, tvb, offset, -1, ett_kafka_renewer, &subti, "Renewer");

    offset = dissect_kafka_string(subtree, hf_kafka_token_principal_type, tvb, pinfo, offset, api_version >= 2, NULL, NULL);

    offset = dissect_kafka_string(subtree, hf_kafka_token_principal_name, tvb, pinfo, offset, api_version >= 2, NULL, NULL);

    if (api_version >= 2) {
        offset = dissect_kafka_tagged_fields(tvb, pinfo, subtree, offset, 0);
    }

    proto_item_set_end(subti, tvb, offset);

    return offset;
}

static int
dissect_kafka_create_delegation_token_request(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset,
                                        kafka_api_version_t api_version)
{
    proto_item *subti;
    proto_tree *subtree;

    subtree = proto_tree_add_subtree(tree, tvb, offset, -1,
                                     ett_kafka_renewers,
                                     &subti, "Renewers");

    offset = dissect_kafka_array(subtree, tvb, pinfo, offset, api_version >= 2, api_version,
                                 &dissect_kafka_create_delegation_token_request_renewer, NULL);

    proto_item_set_end(subti, tvb, offset);

    offset = dissect_kafka_int64(tree, hf_kafka_token_max_life_time, tvb, pinfo, offset, NULL);

    if (api_version >= 2) {
        offset = dissect_kafka_tagged_fields(tvb, pinfo, tree, offset, 0);
    }

    return offset;
}

static int
dissect_kafka_create_delegation_token_response(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset,
                                         kafka_api_version_t api_version)
{
    offset = dissect_kafka_error(tvb, pinfo, tree, offset);

    offset = dissect_kafka_string(tree, hf_kafka_token_principal_type, tvb, pinfo, offset, api_version >= 2, NULL, NULL);

    offset = dissect_kafka_string(tree, hf_kafka_token_principal_name, tvb, pinfo, offset, api_version >= 2, NULL, NULL);

    offset = dissect_kafka_timestamp(tree, hf_kafka_token_issue_timestamp, tvb, pinfo, offset, NULL);

    offset = dissect_kafka_timestamp(tree, hf_kafka_token_expiry_timestamp, tvb, pinfo, offset, NULL);

    offset = dissect_kafka_timestamp(tree, hf_kafka_token_max_timestamp, tvb, pinfo, offset, NULL);

    offset = dissect_kafka_string(tree, hf_kafka_token_id, tvb, pinfo, offset, api_version >= 2, NULL, NULL);

    offset = dissect_kafka_bytes(tree, hf_kafka_token_hmac, tvb, pinfo, offset, api_version >= 2, NULL, NULL);

    offset = dissect_kafka_throttle_time(tvb, pinfo, tree, offset);

    if (api_version >= 2) {
        offset = dissect_kafka_tagged_fields(tvb, pinfo, tree, offset, 0);
    }

    return offset;
}

/* RENEW_DELEGATION_TOKEN REQUEST/RESPONSE */

static int
dissect_kafka_renew_delegation_token_request(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset,
                                              kafka_api_version_t api_version)
{
    offset = dissect_kafka_bytes(tree, hf_kafka_token_hmac, tvb, pinfo, offset, api_version >= 2, NULL, NULL);

    offset = dissect_kafka_int64(tree, hf_kafka_token_renew_time, tvb, pinfo, offset, NULL);

    if (api_version >= 2) {
        offset = dissect_kafka_tagged_fields(tvb, pinfo, tree, offset, 0);
    }

    return offset;
}

static int
dissect_kafka_renew_delegation_token_response(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset,
                                               kafka_api_version_t api_version)
{
    offset = dissect_kafka_error(tvb, pinfo, tree, offset);

    offset = dissect_kafka_timestamp(tree, hf_kafka_token_expiry_timestamp, tvb, pinfo, offset, NULL);

    offset = dissect_kafka_throttle_time(tvb, pinfo, tree, offset);

    if (api_version >= 2) {
        offset = dissect_kafka_tagged_fields(tvb, pinfo, tree, offset, 0);
    }

    return offset;
}

/* EXPIRE_DELEGATION_TOKEN REQUEST/RESPONSE */

static int
dissect_kafka_expire_delegation_token_request(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset,
                                             kafka_api_version_t api_version)
{
    offset = dissect_kafka_bytes(tree, hf_kafka_token_hmac, tvb, pinfo, offset, api_version >= 2, NULL, NULL);

    offset = dissect_kafka_int64(tree, hf_kafka_token_expiry_time, tvb, pinfo, offset, NULL);

    if (api_version >= 2) {
        offset = dissect_kafka_tagged_fields(tvb, pinfo, tree, offset, 0);
    }

    return offset;
}

static int
dissect_kafka_expire_delegation_token_response(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset,
                                              kafka_api_version_t api_version _U_)
{
    offset = dissect_kafka_error(tvb, pinfo, tree, offset);

    offset = dissect_kafka_timestamp(tree, hf_kafka_token_expiry_timestamp, tvb, pinfo, offset, NULL);

    offset = dissect_kafka_throttle_time(tvb, pinfo, tree, offset);

    if (api_version >= 2) {
        offset = dissect_kafka_tagged_fields(tvb, pinfo, tree, offset, 0);
    }

    return offset;
}

/* DESCRIBE_DELEGATION_TOKEN REQUEST/RESPONSE */

static int
dissect_kafka_describe_delegation_token_request_owner(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                                                      int offset, kafka_api_version_t api_version)
{
    proto_item *subti;
    proto_tree *subtree;

    subtree = proto_tree_add_subtree(tree, tvb, offset, -1, ett_kafka_owner, &subti, "Owner");

    offset = dissect_kafka_string(subtree, hf_kafka_token_principal_type, tvb, pinfo, offset, api_version >= 2, NULL, NULL);

    offset = dissect_kafka_string(subtree, hf_kafka_token_principal_name, tvb, pinfo, offset, api_version >= 2, NULL, NULL);

    if (api_version >= 2) {
        offset = dissect_kafka_tagged_fields(tvb, pinfo, subtree, offset, 0);
    }

    proto_item_set_end(subti, tvb, offset);

    return offset;
}

static int
dissect_kafka_describe_delegation_token_request(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset,
                                              kafka_api_version_t api_version)
{
    proto_item *subti;
    proto_tree *subtree;

    subtree = proto_tree_add_subtree(tree, tvb, offset, -1,
                                     ett_kafka_owners,
                                     &subti, "Owners");
    offset = dissect_kafka_array(subtree, tvb, pinfo, offset, api_version >= 2, api_version,
                                 &dissect_kafka_describe_delegation_token_request_owner, NULL);
    proto_item_set_end(subti, tvb, offset);

    if (api_version >= 2) {
        offset = dissect_kafka_tagged_fields(tvb, pinfo, tree, offset, 0);
    }

    return offset;
}

static int
dissect_kafka_describe_delegation_token_response_renewer(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                                                     int offset, kafka_api_version_t api_version)
{
    proto_item *subti;
    proto_tree *subtree;

    subtree = proto_tree_add_subtree(tree, tvb, offset, -1, ett_kafka_renewer, &subti, "Renewer");

    offset = dissect_kafka_string(subtree, hf_kafka_token_principal_type, tvb, pinfo, offset, api_version >= 2, NULL, NULL);
    offset = dissect_kafka_string(subtree, hf_kafka_token_principal_name, tvb, pinfo, offset, api_version >= 2, NULL, NULL);

    if (api_version >= 2) {
        offset = dissect_kafka_tagged_fields(tvb, pinfo, subtree, offset, 0);
    }

    proto_item_set_end(subti, tvb, offset);

    return offset;
}

static int
dissect_kafka_describe_delegation_token_response_token(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                                                      int offset, kafka_api_version_t api_version)
{
    proto_item *subti, *subsubti;
    proto_tree *subtree, *subsubtree;

    subtree = proto_tree_add_subtree(tree, tvb, offset, -1, ett_kafka_token, &subti, "Token");

    offset = dissect_kafka_string(subtree, hf_kafka_token_principal_type, tvb, pinfo, offset, api_version >= 2, NULL, NULL);
    offset = dissect_kafka_string(subtree, hf_kafka_token_principal_name, tvb, pinfo, offset, api_version >= 2, NULL, NULL);

    offset = dissect_kafka_timestamp(subtree, hf_kafka_token_issue_timestamp, tvb, pinfo, offset, NULL);

    offset = dissect_kafka_timestamp(subtree, hf_kafka_token_expiry_timestamp, tvb, pinfo, offset, NULL);

    offset = dissect_kafka_timestamp(subtree, hf_kafka_token_max_timestamp, tvb, pinfo, offset, NULL);

    offset = dissect_kafka_string(subtree, hf_kafka_token_id, tvb, pinfo, offset, api_version >= 2, NULL, NULL);
    offset = dissect_kafka_bytes(subtree, hf_kafka_token_hmac, tvb, pinfo, offset, api_version >= 2, NULL, NULL);

    subsubtree = proto_tree_add_subtree(subtree, tvb, offset, -1,
                                     ett_kafka_renewers,
                                     &subsubti, "Renewers");
    offset = dissect_kafka_array(subsubtree, tvb, pinfo, offset, api_version >= 2, api_version,
                                 &dissect_kafka_describe_delegation_token_response_renewer, NULL);
    proto_item_set_end(subsubti, tvb, offset);

    if (api_version >= 2) {
        offset = dissect_kafka_tagged_fields(tvb, pinfo, subtree, offset, 0);
    }

    proto_item_set_end(subti, tvb, offset);

    return offset;
}

static int
dissect_kafka_describe_delegation_token_response(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset,
                                               kafka_api_version_t api_version)
{
    proto_item *subti;
    proto_tree *subtree;

    offset = dissect_kafka_error(tvb, pinfo, tree, offset);

    subtree = proto_tree_add_subtree(tree, tvb, offset, -1,
                                     ett_kafka_tokens,
                                     &subti, "Tokens");
    offset = dissect_kafka_array(subtree, tvb, pinfo, offset, api_version >= 2, api_version,
                                 &dissect_kafka_describe_delegation_token_response_token, NULL);
    proto_item_set_end(subti, tvb, offset);

    offset = dissect_kafka_throttle_time(tvb, pinfo, tree, offset);

    if (api_version >= 2) {
        offset = dissect_kafka_tagged_fields(tvb, pinfo, tree, offset, 0);
    }

    return offset;
}

/* DELETE_GROUPS REQUEST/RESPONSE */

static int
dissect_kafka_delete_groups_request_group(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                                                      int offset, kafka_api_version_t api_version)
{
    offset = dissect_kafka_string(tree, hf_kafka_consumer_group, tvb, pinfo, offset, api_version >= 2, NULL, NULL);
    return offset;
}

static int
dissect_kafka_delete_groups_request(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset,
                                                kafka_api_version_t api_version _U_)
{
    proto_item *subti;
    proto_tree *subtree;

    subtree = proto_tree_add_subtree(tree, tvb, offset, -1,
                                     ett_kafka_groups,
                                     &subti, "Groups");

    offset = dissect_kafka_array(subtree, tvb, pinfo, offset, api_version >= 2, api_version,
                                 &dissect_kafka_delete_groups_request_group, NULL);

    if (api_version >= 2) {
        offset = dissect_kafka_tagged_fields(tvb, pinfo, tree, offset, 0);
    }

    proto_item_set_end(subti, tvb, offset);

    return offset;
}

static int
dissect_kafka_delete_groups_response_group(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                                                         int offset, kafka_api_version_t api_version _U_)
{
    proto_item *subti;
    proto_tree *subtree;

    subtree = proto_tree_add_subtree(tree, tvb, offset, -1, ett_kafka_group, &subti, "Group");

    offset = dissect_kafka_string(subtree, hf_kafka_consumer_group, tvb, pinfo, offset, api_version >= 2, NULL, NULL);

    offset = dissect_kafka_error(tvb, pinfo, subtree, offset);

    if (api_version >= 2) {
        offset = dissect_kafka_tagged_fields(tvb, pinfo, subtree, offset, 0);
    }

    proto_item_set_end(subti, tvb, offset);

    return offset;
}

static int
dissect_kafka_delete_groups_response(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset,
                                                 kafka_api_version_t api_version _U_)
{
    proto_item *subti;
    proto_tree *subtree;

    offset = dissect_kafka_throttle_time(tvb, pinfo, tree, offset);

    subtree = proto_tree_add_subtree(tree, tvb, offset, -1,
                                     ett_kafka_groups,
                                     &subti, "Groups");

    offset = dissect_kafka_array(subtree, tvb, pinfo, offset, api_version >= 2, api_version,
                                 &dissect_kafka_delete_groups_response_group, NULL);

    if (api_version >= 2) {
        offset = dissect_kafka_tagged_fields(tvb, pinfo, tree, offset, 0);
    }

    proto_item_set_end(subti, tvb, offset);

    return offset;
}

/* ELECT_LEADERS REQUEST/RESPONSE */

static int
dissect_kafka_elect_leaders_request_partition(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                                          int offset, kafka_api_version_t api_version _U_)
{
    return dissect_kafka_int32(tree, hf_kafka_partition_id, tvb, pinfo, offset, NULL);
}

static int
dissect_kafka_elect_leaders_request_topic(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset,
                                    kafka_api_version_t api_version)
{
    proto_item *subti, *subsubti;
    proto_tree *subtree, *subsubtree;

    subtree = proto_tree_add_subtree(tree, tvb, offset, -1,
                                     ett_kafka_topic,
                                     &subti, "Topic");

    subsubtree = proto_tree_add_subtree(subtree, tvb, offset, -1,
                                     ett_kafka_partitions,
                                     &subsubti, "Partitions");
    offset = dissect_kafka_array(subsubtree, tvb, pinfo, offset, api_version >= 2, api_version,
                                 &dissect_kafka_elect_leaders_request_partition, NULL);
    proto_item_set_end(subsubti, tvb, offset);

    if (api_version >= 2) {
        offset = dissect_kafka_tagged_fields(tvb, pinfo, subtree, offset, 0);
    }

    proto_item_set_end(subti, tvb, offset);

    return offset;
}

static int
dissect_kafka_elect_leaders_request(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset,
                                    kafka_api_version_t api_version)
{
    proto_item *subti;
    proto_tree *subtree;

    if (api_version >= 1) {
        offset = dissect_kafka_int8(tree, hf_kafka_election_type, tvb, pinfo, offset, NULL);
    }

    subtree = proto_tree_add_subtree(tree, tvb, offset, -1,
                                     ett_kafka_topics,
                                     &subti, "Topics");
    offset = dissect_kafka_array(subtree, tvb, pinfo, offset, api_version >= 2, api_version,
                                 &dissect_kafka_elect_leaders_request_topic, NULL);
    proto_item_set_end(subti, tvb, offset);

    offset = dissect_kafka_int32(tree, hf_kafka_timeout, tvb, pinfo, offset, NULL);

    if (api_version >= 2) {
        offset = dissect_kafka_tagged_fields(tvb, pinfo, tree, offset, 0);
    }

    return offset;

}

static int
dissect_kafka_elect_leaders_response_partition(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                                                  int offset, kafka_api_version_t api_version)
{

    proto_item *subti;
    proto_tree *subtree;

    subtree = proto_tree_add_subtree(tree, tvb, offset, -1,
                                     ett_kafka_partition,
                                     &subti, "Partition");

    offset = dissect_kafka_int32(subtree, hf_kafka_partition_id, tvb, pinfo, offset, NULL);

    offset = dissect_kafka_error(tvb, pinfo, subtree, offset);

    offset = dissect_kafka_string(subtree, hf_kafka_error_message, tvb, pinfo, offset, api_version >= 2, NULL, NULL);

    if (api_version >= 2) {
        offset = dissect_kafka_tagged_fields(tvb, pinfo, subtree, offset, 0);
    }

    proto_item_set_end(subti, tvb, offset);

    return offset;
}

static int
dissect_kafka_elect_leaders_response_topic(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset,
                                              kafka_api_version_t api_version)
{
    proto_item *subti, *subsubti;
    proto_tree *subtree, *subsubtree;

    subtree = proto_tree_add_subtree(tree, tvb, offset, -1,
                                     ett_kafka_topic,
                                     &subti, "Topic");

    offset = dissect_kafka_string(subtree, hf_kafka_topic_name, tvb, pinfo, offset, api_version >= 2, NULL, NULL);

    subsubtree = proto_tree_add_subtree(subtree, tvb, offset, -1,
                                        ett_kafka_partitions,
                                        &subsubti, "Partitions");
    offset = dissect_kafka_array(subsubtree, tvb, pinfo, offset, api_version >= 2, api_version,
                                 &dissect_kafka_elect_leaders_response_partition, NULL);
    proto_item_set_end(subsubti, tvb, offset);

    if (api_version >= 2) {
        offset = dissect_kafka_tagged_fields(tvb, pinfo, subtree, offset, 0);
    }

    proto_item_set_end(subti, tvb, offset);

    return offset;
}

static int
dissect_kafka_elect_leaders_response(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset,
                                        kafka_api_version_t api_version)
{
    proto_item *subti;
    proto_tree *subtree;

    offset = dissect_kafka_throttle_time(tvb, pinfo, tree, offset);

    if (api_version >= 1) {
        offset = dissect_kafka_error(tvb, pinfo, tree, offset);
    }

    subtree = proto_tree_add_subtree(tree, tvb, offset, -1,
                                     ett_kafka_topics,
                                     &subti, "Topics");

    offset = dissect_kafka_array(subtree, tvb, pinfo, offset, api_version >= 2, api_version,
                                 &dissect_kafka_elect_leaders_response_topic, NULL);

    proto_item_set_end(subti, tvb, offset);

    if (api_version >= 2) {
        offset = dissect_kafka_tagged_fields(tvb, pinfo, tree, offset, 0);
    }

    return offset;
}

/* INCREMENTAL_ALTER_CONFIGS REQUEST/RESPONSE */

static int
dissect_kafka_inc_alter_config_request_entry(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                                         int offset, kafka_api_version_t api_version)
{
    proto_item *subti;
    proto_tree *subtree;

    subtree = proto_tree_add_subtree(tree, tvb, offset, -1, ett_kafka_config_entry, &subti, "Entry");

    offset = dissect_kafka_string(subtree, hf_kafka_config_key, tvb, pinfo, offset, api_version >= 1, NULL, NULL);

    proto_tree_add_item(subtree, hf_kafka_config_operation, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;

    offset = dissect_kafka_string(subtree, hf_kafka_config_value, tvb, pinfo, offset, api_version >= 1, NULL, NULL);

    if (api_version >= 1) {
        offset = dissect_kafka_tagged_fields(tvb, pinfo, subtree, offset, 0);
    }

    proto_item_set_end(subti, tvb, offset);

    return offset;
}

static int
dissect_kafka_inc_alter_config_request_resource(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                                            int offset, kafka_api_version_t api_version)
{
    proto_item *subti, *subsubti;
    proto_tree *subtree, *subsubtree;

    subtree = proto_tree_add_subtree(tree, tvb, offset, -1, ett_kafka_resource, &subti, "Resource");

    proto_tree_add_item(subtree, hf_kafka_config_resource_type, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;

    offset = dissect_kafka_string(subtree, hf_kafka_config_resource_name, tvb, pinfo, offset, api_version >= 1, NULL, NULL);

    subsubtree = proto_tree_add_subtree(subtree, tvb, offset, -1, ett_kafka_config_entries, &subsubti, "Entries");
    offset = dissect_kafka_array(subsubtree, tvb, pinfo, offset, api_version >= 1, api_version,
                                 &dissect_kafka_inc_alter_config_request_entry, NULL);
    proto_item_set_end(subsubti, tvb, offset);

    if (api_version >= 1) {
        offset = dissect_kafka_tagged_fields(tvb, pinfo, subtree, offset, 0);
    }

    proto_item_set_end(subti, tvb, offset);

    return offset;
}

static int
dissect_kafka_inc_alter_configs_request(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset,
                                    kafka_api_version_t api_version)
{
    proto_item *subti;
    proto_tree *subtree;

    subtree = proto_tree_add_subtree(tree, tvb, offset, -1,
                                     ett_kafka_resources,
                                     &subti, "Resources");

    offset = dissect_kafka_array(subtree, tvb, pinfo, offset, api_version >= 1, api_version,
                                 &dissect_kafka_inc_alter_config_request_resource, NULL);

    proto_item_set_end(subti, tvb, offset);

    proto_tree_add_item(tree, hf_kafka_validate_only, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;

    if (api_version >= 1) {
        offset = dissect_kafka_tagged_fields(tvb, pinfo, tree, offset, 0);
    }

    return offset;
}

static int
dissect_kafka_inc_alter_configs_response_resource(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                                              int offset, kafka_api_version_t api_version)
{
    proto_item *subti;
    proto_tree *subtree;

    subtree = proto_tree_add_subtree(tree, tvb, offset, -1, ett_kafka_resource, &subti, "Resource");

    offset = dissect_kafka_error(tvb, pinfo, subtree, offset);

    offset = dissect_kafka_string(subtree, hf_kafka_error_message, tvb, pinfo, offset, api_version >= 1, NULL, NULL);

    proto_tree_add_item(subtree, hf_kafka_config_resource_type, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;

    offset = dissect_kafka_string(subtree, hf_kafka_config_resource_name, tvb, pinfo, offset, api_version >= 1, NULL, NULL);

    if (api_version >= 1) {
        offset = dissect_kafka_tagged_fields(tvb, pinfo, subtree, offset, 0);
    }

    proto_item_set_end(subti, tvb, offset);

    return offset;
}

static int
dissect_kafka_inc_alter_configs_response(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset,
                                     kafka_api_version_t api_version)
{
    proto_item *subti;
    proto_tree *subtree;

    offset = dissect_kafka_throttle_time(tvb, pinfo, tree, offset);

    subtree = proto_tree_add_subtree(tree, tvb, offset, -1,
                                     ett_kafka_resources,
                                     &subti, "Resources");
    offset = dissect_kafka_array(subtree, tvb, pinfo, offset, api_version >= 1, api_version,
                                 &dissect_kafka_inc_alter_configs_response_resource, NULL);
    proto_item_set_end(subti, tvb, offset);

    if (api_version >= 1) {
        offset = dissect_kafka_tagged_fields(tvb, pinfo, tree, offset, 0);
    }

    return offset;
}

/* ALTER_PARTITION_REASSIGNMENTS REQUEST/RESPONSE */

static int
dissect_kafka_alter_partition_reassignments_request_replica(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree,
                                             int offset, kafka_api_version_t api_version _U_)
{
    proto_tree_add_item(tree, hf_kafka_replica, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;
    return offset;
}

static int
dissect_kafka_alter_partition_reassignments_request_partition(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                                                          int offset, kafka_api_version_t api_version)
{
    proto_item *subti, *subsubti;
    proto_tree *subtree, *subsubtree;
    kafka_partition_t partition;

    subtree = proto_tree_add_subtree(tree, tvb, offset, -1, ett_kafka_partition, &subti, "Partition");

    offset = dissect_kafka_partition_id_ret(tvb, pinfo, subtree, offset, &partition);

    subsubtree = proto_tree_add_subtree(tree, tvb, offset, -1, ett_kafka_partitions, &subsubti, "Replicas");

    offset = dissect_kafka_array(subsubtree, tvb, pinfo, offset, 0, api_version,
                                 &dissect_kafka_alter_partition_reassignments_request_replica, NULL);

    proto_item_set_end(subti, tvb, offset);

    return offset;
}

static int
dissect_kafka_alter_partition_reassignments_request_topic(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                                                int offset, kafka_api_version_t api_version)
{
    proto_item *subti, *subsubti;
    proto_tree *subtree, *subsubtree;

    subtree = proto_tree_add_subtree(tree, tvb, offset, -1, ett_kafka_topic, &subti, "Topic");

    offset = dissect_kafka_string(subtree, hf_kafka_topic_name, tvb, pinfo, offset, 0, NULL, NULL);

    subsubtree = proto_tree_add_subtree(tree, tvb, offset, -1, ett_kafka_partitions, &subsubti, "Partitions");

    offset = dissect_kafka_array(subsubtree, tvb, pinfo, offset, 0, api_version,
                                 &dissect_kafka_alter_partition_reassignments_request_partition, NULL);

    proto_item_set_end(subti, tvb, offset);

    return offset;
}

static int
dissect_kafka_alter_partition_reassignments_request(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset,
                                        kafka_api_version_t api_version)
{
    proto_item *subti;
    proto_tree *subtree;

    proto_tree_add_item(tree, hf_kafka_timeout, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;

    subtree = proto_tree_add_subtree(tree, tvb, offset, -1,
                                     ett_kafka_topics,
                                     &subti, "Topics");
    offset = dissect_kafka_array(subtree, tvb, pinfo, offset, 0, api_version,
                                 &dissect_kafka_alter_partition_reassignments_request_topic, NULL);

    proto_item_set_end(subti, tvb, offset);

    return offset;
}

static int
dissect_kafka_alter_partition_reassignments_response_partition(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                                                              int offset, kafka_api_version_t api_version _U_)
{
    proto_item *subti;
    proto_tree *subtree;
    kafka_partition_t partition;

    subtree = proto_tree_add_subtree(tree, tvb, offset, -1, ett_kafka_partition, &subti, "Partition");

    offset = dissect_kafka_partition_id_ret(tvb, pinfo, subtree, offset, &partition);

    offset = dissect_kafka_error(tvb, pinfo, subtree, offset);

    offset = dissect_kafka_string(subtree, hf_kafka_error_message, tvb, pinfo, offset, 0, NULL, NULL);

    proto_item_set_end(subti, tvb, offset);

    return offset;
}

static int
dissect_kafka_alter_partition_reassignments_response_topic(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                                                          int offset, kafka_api_version_t api_version)
{
    proto_item *subti, *subsubti;
    proto_tree *subtree, *subsubtree;

    subtree = proto_tree_add_subtree(tree, tvb, offset, -1, ett_kafka_topic, &subti, "Topic");

    offset = dissect_kafka_string(subtree, hf_kafka_topic_name, tvb, pinfo, offset, 0, NULL, NULL);

    subsubtree = proto_tree_add_subtree(tree, tvb, offset, -1, ett_kafka_partitions, &subsubti, "Partitions");

    offset = dissect_kafka_array(subsubtree, tvb, pinfo, offset, 0, api_version,
                                 &dissect_kafka_alter_partition_reassignments_response_partition, NULL);

    proto_item_set_end(subti, tvb, offset);

    return offset;
}

static int
dissect_kafka_alter_partition_reassignments_response(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset,
                                                    kafka_api_version_t api_version)
{
    proto_item *subti;
    proto_tree *subtree;

    offset = dissect_kafka_throttle_time(tvb, pinfo, tree, offset);

    offset = dissect_kafka_error(tvb, pinfo, tree, offset);

    offset = dissect_kafka_string(tree, hf_kafka_error_message, tvb, pinfo, offset, 0, NULL, NULL);

    subtree = proto_tree_add_subtree(tree, tvb, offset, -1,
                                     ett_kafka_topics,
                                     &subti, "Topics");
    offset = dissect_kafka_array(subtree, tvb, pinfo, offset, 0, api_version,
                                 &dissect_kafka_alter_partition_reassignments_response_topic, NULL);

    proto_item_set_end(subti, tvb, offset);

    return offset;
}

/* LIST_PARTITION_REASSIGNMENTS REQUEST/RESPONSE */

static int
dissect_kafka_list_partition_reassignments_request_partition(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree,
                                                              int offset, kafka_api_version_t api_version _U_)
{
    proto_tree_add_item(tree, hf_kafka_partition_id, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;

    return offset;
}

static int
dissect_kafka_list_partition_reassignments_request_topic(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                                                          int offset, kafka_api_version_t api_version)
{
    proto_item *subti, *subsubti;
    proto_tree *subtree, *subsubtree;

    subtree = proto_tree_add_subtree(tree, tvb, offset, -1, ett_kafka_topic, &subti, "Topic");

    offset = dissect_kafka_string(subtree, hf_kafka_topic_name, tvb, pinfo, offset, api_version >= 0, NULL, NULL);

    subsubtree = proto_tree_add_subtree(subtree, tvb, offset, -1, ett_kafka_partitions, &subsubti, "Partitions");

    offset = dissect_kafka_array(subsubtree, tvb, pinfo, offset, api_version >= 0, api_version,
                                 &dissect_kafka_list_partition_reassignments_request_partition, NULL);

    proto_item_set_end(subti, tvb, offset);

    offset = dissect_kafka_tagged_fields(tvb, pinfo, subtree, offset, 0);

    return offset;
}

static int
dissect_kafka_list_partition_reassignments_request(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset,
                                                    kafka_api_version_t api_version)
{
    proto_item *subti;
    proto_tree *subtree;

    proto_tree_add_item(tree, hf_kafka_timeout, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;

    subtree = proto_tree_add_subtree(tree, tvb, offset, -1,
                                     ett_kafka_topics,
                                     &subti, "Topics");
    offset = dissect_kafka_array(subtree, tvb, pinfo, offset, api_version >= 0, api_version,
                                 &dissect_kafka_list_partition_reassignments_request_topic, NULL);

    proto_item_set_end(subti, tvb, offset);

    offset = dissect_kafka_tagged_fields(tvb, pinfo, tree, offset, 0);

    return offset;
}

static int
dissect_kafka_list_partition_reassignments_response_replica(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree,
                                                             int offset, kafka_api_version_t api_version _U_)
{
    proto_tree_add_item(tree, hf_kafka_replica, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;

    return offset;
}

static int
dissect_kafka_list_partition_reassignments_response_partition(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                                                               int offset, kafka_api_version_t api_version)
{
    proto_item *subti, *subsubti;
    proto_tree *subtree, *subsubtree;
    kafka_partition_t partition;

    subtree = proto_tree_add_subtree(tree, tvb, offset, -1, ett_kafka_partition, &subti, "Partition");

    offset = dissect_kafka_partition_id_ret(tvb, pinfo, subtree, offset, &partition);

    offset = dissect_kafka_error(tvb, pinfo, subtree, offset);

    offset = dissect_kafka_string(subtree, hf_kafka_error_message, tvb, pinfo, offset, api_version >= 0, NULL, NULL);

    subsubtree = proto_tree_add_subtree(subtree, tvb, offset, -1,
                                        ett_kafka_replicas,
                                        &subsubti, "Current Replicas");
    offset = dissect_kafka_array(subsubtree, tvb, pinfo, offset, api_version >= 0, api_version,
                                 &dissect_kafka_list_partition_reassignments_response_replica, NULL);
    proto_item_set_end(subsubti, tvb, offset);

    subsubtree = proto_tree_add_subtree(subtree, tvb, offset, -1,
                                        ett_kafka_replicas,
                                        &subsubti, "Adding Replicas");
    offset = dissect_kafka_array(subsubtree, tvb, pinfo, offset, api_version >= 0, api_version,
                                 &dissect_kafka_list_partition_reassignments_response_replica, NULL);
    proto_item_set_end(subsubti, tvb, offset);

    subsubtree = proto_tree_add_subtree(subtree, tvb, offset, -1,
                                        ett_kafka_replicas,
                                        &subsubti, "Removing Replicas");
    offset = dissect_kafka_array(subsubtree, tvb, pinfo, offset, api_version >= 0, api_version,
                                 &dissect_kafka_list_partition_reassignments_response_replica, NULL);
    proto_item_set_end(subsubti, tvb, offset);

    offset = dissect_kafka_tagged_fields(tvb, pinfo, subtree, offset, 0);

    proto_item_set_end(subti, tvb, offset);

    return offset;
}

static int
dissect_kafka_list_partition_reassignments_response_topic(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                                                           int offset, kafka_api_version_t api_version)
{
    proto_item *subti, *subsubti;
    proto_tree *subtree, *subsubtree;

    subtree = proto_tree_add_subtree(tree, tvb, offset, -1, ett_kafka_topic, &subti, "Topic");

    offset = dissect_kafka_string(subtree, hf_kafka_topic_name, tvb, pinfo, offset, api_version >= 0, NULL, NULL);

    subsubtree = proto_tree_add_subtree(tree, tvb, offset, -1, ett_kafka_partitions, &subsubti, "Partitions");

    offset = dissect_kafka_array(subsubtree, tvb, pinfo, offset, api_version >= 0, api_version,
                                 &dissect_kafka_list_partition_reassignments_response_partition, NULL);

    offset = dissect_kafka_tagged_fields(tvb, pinfo, subtree, offset, 0);

    proto_item_set_end(subti, tvb, offset);

    return offset;
}

static int
dissect_kafka_list_partition_reassignments_response(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset,
                                                     kafka_api_version_t api_version)
{
    proto_item *subti;
    proto_tree *subtree;

    offset = dissect_kafka_throttle_time(tvb, pinfo, tree, offset);

    offset = dissect_kafka_error(tvb, pinfo, tree, offset);

    offset = dissect_kafka_string(tree, hf_kafka_error_message, tvb, pinfo, offset, api_version >= 0, NULL, NULL);

    subtree = proto_tree_add_subtree(tree, tvb, offset, -1,
                                     ett_kafka_topics,
                                     &subti, "Topics");
    offset = dissect_kafka_array(subtree, tvb, pinfo, offset, api_version >= 0, api_version,
                                 &dissect_kafka_list_partition_reassignments_response_topic, NULL);

    proto_item_set_end(subti, tvb, offset);

    offset = dissect_kafka_tagged_fields(tvb, pinfo, tree, offset, 0);

    return offset;
}

/* OFFSET_DELETE REQUEST/RESPONSE */

static int
dissect_kafka_offset_delete_request_topic(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset,
                                    kafka_api_version_t api_version)
{
    proto_item *subti, *subsubti;
    proto_tree *subtree, *subsubtree;

    subtree = proto_tree_add_subtree(tree, tvb, offset, -1,
                                     ett_kafka_topic,
                                     &subti, "Topic");

    offset = dissect_kafka_string(subtree, hf_kafka_topic_name, tvb, pinfo, offset, 0, NULL, NULL);

    subsubtree = proto_tree_add_subtree(subtree, tvb, offset, -1,
                                     ett_kafka_partitions,
                                     &subsubti, "Partitions");

    offset = dissect_kafka_array(subsubtree, tvb, pinfo, offset, 0, api_version,
                                 &dissect_kafka_partition_id, NULL);

    proto_item_set_end(subti, tvb, offset);

    proto_item_set_end(subsubti, tvb, offset);

    return offset;
}

static int
dissect_kafka_offset_delete_request(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset,
                                        kafka_api_version_t api_version)
{
    proto_item *subti;
    proto_tree *subtree;

    offset = dissect_kafka_string(tree, hf_kafka_consumer_group, tvb, pinfo, offset, 0, NULL, NULL);

    subtree = proto_tree_add_subtree(tree, tvb, offset, -1,
                                     ett_kafka_topics,
                                     &subti, "Topics");

    offset = dissect_kafka_array(subtree, tvb, pinfo, offset, 0, api_version,
                                 &dissect_kafka_offset_delete_request_topic, NULL);

    proto_item_set_end(subti, tvb, offset);

    return offset;
}

static int
dissect_kafka_offset_delete_response_topic_partition(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset,
                                          kafka_api_version_t api_version)
{
    proto_item *subti;
    proto_tree *subtree;

    subtree = proto_tree_add_subtree(tree, tvb, offset, -1,
                                     ett_kafka_partition,
                                     &subti, "Partition");

    offset = dissect_kafka_partition_id(tvb, pinfo, subtree, offset, api_version);

    offset = dissect_kafka_error(tvb, pinfo, subtree, offset);

    proto_item_set_end(subti, tvb, offset);

    return offset;
}

static int
dissect_kafka_offset_delete_response_topic(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset,
                                          kafka_api_version_t api_version)
{
    proto_item *subti, *subsubti;
    proto_tree *subtree, *subsubtree;

    subtree = proto_tree_add_subtree(tree, tvb, offset, -1,
                                     ett_kafka_topic,
                                     &subti, "Topic");

    offset = dissect_kafka_string(subtree, hf_kafka_topic_name, tvb, pinfo, offset, 0, NULL, NULL);

    subsubtree = proto_tree_add_subtree(subtree, tvb, offset, -1,
                                     ett_kafka_partitions,
                                     &subsubti, "Partitions");

    offset = dissect_kafka_array(subsubtree, tvb, pinfo, offset, 0, api_version,
                                 &dissect_kafka_offset_delete_response_topic_partition, NULL);

    proto_item_set_end(subsubti, tvb, offset);

    proto_item_set_end(subti, tvb, offset);

    return offset;
}

static int
dissect_kafka_offset_delete_response(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset,
                                    kafka_api_version_t api_version)
{
    proto_item *subti;
    proto_tree *subtree;

    offset = dissect_kafka_error(tvb, pinfo, tree, offset);

    offset = dissect_kafka_throttle_time(tvb, pinfo, tree, offset);

    subtree = proto_tree_add_subtree(tree, tvb, offset, -1,
                                     ett_kafka_topics,
                                     &subti, "Topics");

    offset = dissect_kafka_array(subtree, tvb, pinfo, offset, 0, api_version,
                                 &dissect_kafka_offset_delete_response_topic, NULL);

    proto_item_set_end(subti, tvb, offset);

    return offset;
}

/* DESCRIBE_CLUSTER REQUEST/RESPONSE */
static int
dissect_kafka_describe_cluster_request(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset,
                                       kafka_api_version_t api_version)
{
    /* include_cluster_authorized_operations */
    offset = dissect_kafka_bool(tree, hf_kafka_include_cluster_authorized_ops, tvb, pinfo, offset);

    /* endpoint_type */
    if (api_version >= 1) {
        offset = dissect_kafka_int8(tree, hf_kafka_endpoint_type, tvb, pinfo, offset, NULL);
    }

    offset = dissect_kafka_tagged_fields(tvb, pinfo, tree, offset, 0);

    return offset;
}

static int
dissect_kafka_describe_cluster_response_broker(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset,
                                               kafka_api_version_t api_version)
{
    proto_item *subti;
    proto_tree *subtree;

    subtree = proto_tree_add_subtree(tree, tvb, offset, -1, ett_kafka_topics, &subti, "Broker");

    /* broker_id */
    offset = dissect_kafka_int32(subtree, hf_kafka_broker_nodeid, tvb, pinfo, offset, NULL);

    /* host */
    offset = dissect_kafka_string(subtree, hf_kafka_broker_host, tvb, pinfo, offset, api_version >= 0, NULL, NULL);

    /* port */
    offset = dissect_kafka_int32(subtree, hf_kafka_broker_port, tvb, pinfo, offset, NULL);

    /* rack */
    offset = dissect_kafka_string(subtree, hf_kafka_rack, tvb, pinfo, offset, api_version >= 0, NULL, NULL);

    offset = dissect_kafka_tagged_fields(tvb, pinfo, subtree, offset, 0);

    proto_item_set_end(subti, tvb, offset);

    return offset;
}

static int
dissect_kafka_describe_cluster_response(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset,
                                        kafka_api_version_t api_version)
{
    proto_item *subti;
    proto_tree *subtree;

    /* throttle_time */
    offset = dissect_kafka_int32(tree, hf_kafka_throttle_time, tvb, pinfo, offset, NULL);

    /* error */
    offset = dissect_kafka_error(tvb, pinfo, tree, offset);

    /* error_message */
    offset = dissect_kafka_string(tree, hf_kafka_error_message, tvb, pinfo, offset, api_version >= 0, NULL, NULL);

    /* endpoint_type */
    if (api_version >= 1) {
        offset = dissect_kafka_int8(tree, hf_kafka_endpoint_type, tvb, pinfo, offset, NULL);
    }

    /* cluster_id */
    offset = dissect_kafka_string(tree, hf_kafka_cluster_id, tvb, pinfo, offset, api_version >= 0, NULL, NULL);

    /* controller_id */
    offset = dissect_kafka_int32(tree, hf_kafka_controller_id, tvb, pinfo, offset, NULL);

    /* [brokers] */
    subtree = proto_tree_add_subtree(tree, tvb, offset, -1, ett_kafka_topics, &subti, "Brokers");
    offset = dissect_kafka_array(subtree, tvb, pinfo, offset, api_version >= 0, api_version,
                                 &dissect_kafka_describe_cluster_response_broker, NULL);
    proto_item_set_end(subti, tvb, offset);

    /* cluster_authorized_operations */
    offset = dissect_kafka_int32(tree, hf_kafka_cluster_authorized_ops, tvb, pinfo, offset, NULL);

    offset = dissect_kafka_tagged_fields(tvb, pinfo, tree, offset, 0);

    return offset;
}

/* ALLOCATE_PRODUCER_IDS REQUEST/RESPONSE */

static int
dissect_kafka_allocate_producer_ids_request(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset,
                                            kafka_api_version_t api_version _U_)
{
    /* broker_id */
    offset = dissect_kafka_int32(tree, hf_kafka_broker_nodeid, tvb, pinfo, offset, NULL);

    /* broker_epoch */
    offset = dissect_kafka_int64(tree, hf_kafka_broker_epoch, tvb, pinfo, offset, NULL);

    offset = dissect_kafka_tagged_fields(tvb, pinfo, tree, offset, 0);

    return offset;
}

static int
dissect_kafka_allocate_producer_ids_response(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset,
                                             kafka_api_version_t api_version _U_)
{
    /* throttle_time */
    offset = dissect_kafka_int32(tree, hf_kafka_throttle_time, tvb, pinfo, offset, NULL);

    /* error */
    offset = dissect_kafka_error(tvb, pinfo, tree, offset);

    /* producer_id_start */
    offset = dissect_kafka_int64(tree, hf_kafka_producer_id_start, tvb, pinfo, offset, NULL);

    /* producer_id_len */
    offset = dissect_kafka_int32(tree, hf_kafka_producer_id_len, tvb, pinfo, offset, NULL);

    offset = dissect_kafka_tagged_fields(tvb, pinfo, tree, offset, 0);

    return offset;
}

/* MAIN */

static wmem_multimap_t *
dissect_kafka_get_match_map(packet_info *pinfo)
{
    conversation_t         *conversation;
    wmem_multimap_t        *match_map;
    conversation = find_or_create_conversation(pinfo);
    match_map    = (wmem_multimap_t *) conversation_get_proto_data(conversation, proto_kafka);
    if (match_map == NULL) {
        match_map = wmem_multimap_new(wmem_file_scope(), g_direct_hash, g_direct_equal);
        conversation_add_proto_data(conversation, proto_kafka, match_map);

    }
    return match_map;
}

static bool
dissect_kafka_insert_match(packet_info *pinfo, uint32_t correlation_id, kafka_query_response_t *match)
{
    if (wmem_multimap_lookup32(dissect_kafka_get_match_map(pinfo), GUINT_TO_POINTER(correlation_id), pinfo->num)) {
        return 0;
    }
    wmem_multimap_insert32(dissect_kafka_get_match_map(pinfo), GUINT_TO_POINTER(correlation_id), pinfo->num, match);
    return 1;
}

static kafka_query_response_t *
dissect_kafka_lookup_match(packet_info *pinfo, uint32_t correlation_id)
{
    kafka_query_response_t *match = (kafka_query_response_t*)wmem_multimap_lookup32_le(dissect_kafka_get_match_map(pinfo), GUINT_TO_POINTER(correlation_id), pinfo->num);
    return match;
}


static int
dissect_kafka(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
    proto_item             *root_ti, *ti;
    proto_tree             *kafka_tree;
    int                     offset  = 0;
    uint32_t                pdu_length;
    uint32_t                pdu_correlation_id;
    kafka_query_response_t *matcher;
    kafka_api_version_t     dissect_api_version;
    bool                    has_response = 1;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "Kafka");
    col_clear(pinfo->cinfo, COL_INFO);

    root_ti = proto_tree_add_item(tree, proto_kafka, tvb, 0, -1, ENC_NA);

    kafka_tree = proto_item_add_subtree(root_ti, ett_kafka);

    pdu_length = tvb_get_ntohl(tvb, offset);
    proto_tree_add_item(kafka_tree, hf_kafka_len, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;

    if (pinfo->destport == pinfo->match_uint) {

        /* Request (as directed towards server port) */

        /* in the request PDU the correlation id comes after api_key and api_version */
        pdu_correlation_id = tvb_get_ntohl(tvb, offset+4);

        matcher = wmem_new(wmem_file_scope(), kafka_query_response_t);

        matcher->api_key        = tvb_get_ntohs(tvb, offset);
        matcher->api_version    = tvb_get_ntohs(tvb, offset+2);
        matcher->correlation_id = pdu_correlation_id;
        matcher->request_frame  = pinfo->num;
        matcher->response_found = false;
        matcher->flexible_api   = kafka_is_api_version_flexible(matcher->api_key, matcher->api_version);

        col_add_fstr(pinfo->cinfo, COL_INFO, "Kafka %s v%d Request",
                     kafka_api_key_to_str(matcher->api_key),
                     matcher->api_version);

        /* Also add to protocol root */
        proto_item_append_text(root_ti, " (%s v%d Request)",
                               kafka_api_key_to_str(matcher->api_key),
                               matcher->api_version);

        /* for the header implementation check RequestHeaderData class */

        ti = proto_tree_add_item(kafka_tree, hf_kafka_request_api_key, tvb, offset, 2, ENC_BIG_ENDIAN);
        proto_item_set_hidden(ti);

        ti = proto_tree_add_item(kafka_tree, hf_kafka_api_key, tvb, offset, 2, ENC_BIG_ENDIAN);
        offset += 2;
        kafka_check_supported_api_key(pinfo, ti, matcher);

        ti = proto_tree_add_item(kafka_tree, hf_kafka_request_api_version, tvb, offset, 2, ENC_BIG_ENDIAN);
        proto_item_set_hidden(ti);

        ti = proto_tree_add_item(kafka_tree, hf_kafka_api_version, tvb, offset, 2, ENC_BIG_ENDIAN);
        offset += 2;
        dissect_api_version = kafka_check_supported_api_version(pinfo, ti, matcher);

        proto_tree_add_item(kafka_tree, hf_kafka_correlation_id, tvb, offset, 4, ENC_BIG_ENDIAN);
        offset += 4;

        if (matcher->api_key == KAFKA_CONTROLLED_SHUTDOWN && matcher->api_version == 0) {
            /*
             * Special case for ControlledShutdownRequest.
             * https://github.com/apache/kafka/blob/2.5.0/generator/src/main/java/org/apache/kafka/message/ApiMessageTypeGenerator.java#L268-L277
             * The code is materialized in ApiMessageTypes class.
             */
        } else {
            /* even if flexible API is used, clientId is still using int16_t string length prefix */
            offset = dissect_kafka_string(kafka_tree, hf_kafka_client_id, tvb, pinfo, offset, 0, NULL, NULL);
        }

        if (matcher->flexible_api) {
            /* version 2 request header (flexible API) contains list of tagged fields, last param is ignored */
            offset = dissect_kafka_tagged_fields(tvb, pinfo, kafka_tree, offset, 0);
        }

        switch (matcher->api_key) {
            case KAFKA_PRODUCE:
                /* The kafka server always responds, except in the case of a produce
                 * request whose RequiredAcks field is 0. This field is at a dynamic
                 * offset into the request, so to avoid too much prefetch logic we
                 * simply don't queue produce requests here. If it is a produce
                 * request with a non-zero RequiredAcks field it gets queued later.
                 */
                if (tvb_get_ntohs(tvb, offset) == KAFKA_ACK_NOT_REQUIRED) {
                    has_response = 0;
                }
                offset = dissect_kafka_produce_request(tvb, pinfo, kafka_tree, offset, dissect_api_version);
                break;
            case KAFKA_FETCH:
                offset = dissect_kafka_fetch_request(tvb, pinfo, kafka_tree, offset, dissect_api_version);
                break;
            case KAFKA_OFFSETS:
                offset = dissect_kafka_offsets_request(tvb, pinfo, kafka_tree, offset, dissect_api_version);
                break;
            case KAFKA_METADATA:
                offset = dissect_kafka_metadata_request(tvb, pinfo, kafka_tree, offset, dissect_api_version);
                break;
            case KAFKA_LEADER_AND_ISR:
                offset = dissect_kafka_leader_and_isr_request(tvb, pinfo, kafka_tree, offset, dissect_api_version);
                break;
            case KAFKA_STOP_REPLICA:
                offset = dissect_kafka_stop_replica_request(tvb, pinfo, kafka_tree, offset, dissect_api_version);
                break;
            case KAFKA_UPDATE_METADATA:
                offset = dissect_kafka_update_metadata_request(tvb, pinfo, kafka_tree, offset, dissect_api_version);
                break;
            case KAFKA_CONTROLLED_SHUTDOWN:
                offset = dissect_kafka_controlled_shutdown_request(tvb, pinfo, kafka_tree, offset, dissect_api_version);
                break;
            case KAFKA_OFFSET_COMMIT:
                offset = dissect_kafka_offset_commit_request(tvb, pinfo, kafka_tree, offset, dissect_api_version);
                break;
            case KAFKA_OFFSET_FETCH:
                offset = dissect_kafka_offset_fetch_request(tvb, pinfo, kafka_tree, offset, dissect_api_version);
                break;
            case KAFKA_FIND_COORDINATOR:
                offset = dissect_kafka_find_coordinator_request(tvb, pinfo, kafka_tree, offset, dissect_api_version);
                break;
            case KAFKA_JOIN_GROUP:
                offset = dissect_kafka_join_group_request(tvb, pinfo, kafka_tree, offset, dissect_api_version);
                break;
            case KAFKA_HEARTBEAT:
                offset = dissect_kafka_heartbeat_request(tvb, pinfo, kafka_tree, offset, dissect_api_version);
                break;
            case KAFKA_LEAVE_GROUP:
                offset = dissect_kafka_leave_group_request(tvb, pinfo, kafka_tree, offset, dissect_api_version);
                break;
            case KAFKA_SYNC_GROUP:
                offset = dissect_kafka_sync_group_request(tvb, pinfo, kafka_tree, offset, dissect_api_version);
                break;
            case KAFKA_DESCRIBE_GROUPS:
                offset = dissect_kafka_describe_groups_request(tvb, pinfo, kafka_tree, offset, dissect_api_version);
                break;
            case KAFKA_LIST_GROUPS:
                offset = dissect_kafka_list_groups_request(tvb, pinfo, kafka_tree, offset, dissect_api_version);
                break;
            case KAFKA_SASL_HANDSHAKE:
                offset = dissect_kafka_sasl_handshake_request(tvb, pinfo, kafka_tree, offset, dissect_api_version);
                break;
            case KAFKA_API_VERSIONS:
                offset = dissect_kafka_api_versions_request(tvb, pinfo, kafka_tree, offset, dissect_api_version);
                break;
            case KAFKA_CREATE_TOPICS:
                offset = dissect_kafka_create_topics_request(tvb, pinfo, kafka_tree, offset, dissect_api_version);
                break;
            case KAFKA_DELETE_TOPICS:
                offset = dissect_kafka_delete_topics_request(tvb, pinfo, kafka_tree, offset, dissect_api_version);
                break;
            case KAFKA_DELETE_RECORDS:
                offset = dissect_kafka_delete_records_request(tvb, pinfo, kafka_tree, offset, dissect_api_version);
                break;
            case KAFKA_INIT_PRODUCER_ID:
                offset = dissect_kafka_init_producer_id_request(tvb, pinfo, kafka_tree, offset, dissect_api_version);
                break;
            case KAFKA_OFFSET_FOR_LEADER_EPOCH:
                offset = dissect_kafka_offset_for_leader_epoch_request(tvb, pinfo, kafka_tree, offset, dissect_api_version);
                break;
            case KAFKA_ADD_PARTITIONS_TO_TXN:
                offset = dissect_kafka_add_partitions_to_txn_request(tvb, pinfo, kafka_tree, offset, dissect_api_version);
                break;
            case KAFKA_ADD_OFFSETS_TO_TXN:
                offset = dissect_kafka_add_offsets_to_txn_request(tvb, pinfo, kafka_tree, offset, dissect_api_version);
                break;
            case KAFKA_END_TXN:
                offset = dissect_kafka_end_txn_request(tvb, pinfo, kafka_tree, offset, dissect_api_version);
                break;
            case KAFKA_WRITE_TXN_MARKERS:
                offset = dissect_kafka_write_txn_markers_request(tvb, pinfo, kafka_tree, offset, dissect_api_version);
                break;
            case KAFKA_TXN_OFFSET_COMMIT:
                offset = dissect_kafka_txn_offset_commit_request(tvb, pinfo, kafka_tree, offset, dissect_api_version);
                break;
            case KAFKA_DESCRIBE_ACLS:
                offset = dissect_kafka_describe_acls_request(tvb, pinfo, kafka_tree, offset, dissect_api_version);
                break;
            case KAFKA_CREATE_ACLS:
                offset = dissect_kafka_create_acls_request(tvb, pinfo, kafka_tree, offset, dissect_api_version);
                break;
            case KAFKA_DELETE_ACLS:
                offset = dissect_kafka_delete_acls_request(tvb, pinfo, kafka_tree, offset, dissect_api_version);
                break;
            case KAFKA_DESCRIBE_CONFIGS:
                offset = dissect_kafka_describe_configs_request(tvb, pinfo, kafka_tree, offset, dissect_api_version);
                break;
            case KAFKA_ALTER_CONFIGS:
                offset = dissect_kafka_alter_configs_request(tvb, pinfo, kafka_tree, offset, dissect_api_version);
                break;
            case KAFKA_ALTER_REPLICA_LOG_DIRS:
                offset = dissect_kafka_alter_replica_log_dirs_request(tvb, pinfo, kafka_tree, offset, dissect_api_version);
                break;
            case KAFKA_DESCRIBE_LOG_DIRS:
                offset = dissect_kafka_describe_log_dirs_request(tvb, pinfo, kafka_tree, offset, dissect_api_version);
                break;
            case KAFKA_CREATE_PARTITIONS:
                offset = dissect_kafka_create_partitions_request(tvb, pinfo, kafka_tree, offset, dissect_api_version);
                break;
            case KAFKA_SASL_AUTHENTICATE:
                offset = dissect_kafka_sasl_authenticate_request(tvb, pinfo, kafka_tree, offset, dissect_api_version);
                break;
            case KAFKA_CREATE_DELEGATION_TOKEN:
                offset = dissect_kafka_create_delegation_token_request(tvb, pinfo, kafka_tree, offset, dissect_api_version);
                break;
            case KAFKA_RENEW_DELEGATION_TOKEN:
                offset = dissect_kafka_renew_delegation_token_request(tvb, pinfo, kafka_tree, offset, dissect_api_version);
                break;
            case KAFKA_EXPIRE_DELEGATION_TOKEN:
                offset = dissect_kafka_expire_delegation_token_request(tvb, pinfo, kafka_tree, offset, dissect_api_version);
                break;
            case KAFKA_DESCRIBE_DELEGATION_TOKEN:
                offset = dissect_kafka_describe_delegation_token_request(tvb, pinfo, kafka_tree, offset, dissect_api_version);
                break;
            case KAFKA_DELETE_GROUPS:
                offset = dissect_kafka_delete_groups_request(tvb, pinfo, kafka_tree, offset, dissect_api_version);
                break;
            case KAFKA_ELECT_LEADERS:
                offset = dissect_kafka_elect_leaders_request(tvb, pinfo, kafka_tree, offset, dissect_api_version);
                break;
            case KAFKA_INC_ALTER_CONFIGS:
                offset = dissect_kafka_inc_alter_configs_request(tvb, pinfo, kafka_tree, offset, dissect_api_version);
                break;
            case KAFKA_ALTER_PARTITION_REASSIGNMENTS:
                offset = dissect_kafka_alter_partition_reassignments_request(tvb, pinfo, kafka_tree, offset, dissect_api_version);
                break;
            case KAFKA_LIST_PARTITION_REASSIGNMENTS:
                offset = dissect_kafka_list_partition_reassignments_request(tvb, pinfo, kafka_tree, offset, dissect_api_version);
                break;
            case KAFKA_OFFSET_DELETE:
                offset = dissect_kafka_offset_delete_request(tvb, pinfo, kafka_tree, offset, dissect_api_version);
                break;
            case KAFKA_DESCRIBE_CLUSTER:
                offset = dissect_kafka_describe_cluster_request(tvb, pinfo, kafka_tree, offset, dissect_api_version);
                break;
            case KAFKA_ALLOCATE_PRODUCER_IDS:
                offset = dissect_kafka_allocate_producer_ids_request(tvb, pinfo, kafka_tree, offset, dissect_api_version);
                break;
        }

        if (!(has_response && dissect_kafka_insert_match(pinfo, pdu_correlation_id, matcher))) {
            wmem_free(wmem_file_scope(), matcher);
        }

    }
    else {
        /* Response */

        /* in the response PDU the correlation id comes directly after frame length */
        pdu_correlation_id = tvb_get_ntohl(tvb, offset);
        proto_tree_add_item(kafka_tree, hf_kafka_correlation_id, tvb, offset, 4, ENC_BIG_ENDIAN);
        offset += 4;

        matcher = dissect_kafka_lookup_match(pinfo, pdu_correlation_id);

        if (matcher == NULL) {
            col_set_str(pinfo->cinfo, COL_INFO, "Kafka Response (Undecoded, Request Missing)");
            expert_add_info(pinfo, root_ti, &ei_kafka_request_missing);
            return tvb_captured_length(tvb);
        }

        col_add_fstr(pinfo->cinfo, COL_INFO, "Kafka %s v%d Response",
                     kafka_api_key_to_str(matcher->api_key),
                     matcher->api_version);
        /* Also add to protocol root */
        proto_item_append_text(root_ti, " (%s v%d Response)",
                               kafka_api_key_to_str(matcher->api_key),
                               matcher->api_version);


        /* Show request frame */
        ti = proto_tree_add_uint(kafka_tree, hf_kafka_request_frame, tvb,
                0, 0, matcher->request_frame);
        proto_item_set_generated(ti);

        /* Show api key (message type) */
        ti = proto_tree_add_int(kafka_tree, hf_kafka_response_api_key, tvb,
                0, 0, matcher->api_key);
        proto_item_set_generated(ti);
        proto_item_set_hidden(ti);
        ti = proto_tree_add_int(kafka_tree, hf_kafka_api_key, tvb,
                                0, 0, matcher->api_key);
        proto_item_set_generated(ti);
        kafka_check_supported_api_key(pinfo, ti, matcher);

        /* Also show api version from request */
        ti = proto_tree_add_int(kafka_tree, hf_kafka_response_api_version, tvb,
                                0, 0, matcher->api_version);
        proto_item_set_generated(ti);
        dissect_api_version = kafka_check_supported_api_version(pinfo, ti, matcher);

        if (matcher->api_key == KAFKA_API_VERSIONS) {
            /*
             * Special case for ApiVersions.
             * https://cwiki.apache.org/confluence/display/KAFKA/KIP-511%3A+Collect+and+Expose+Client%27s+Name+and+Version+in+the+Brokers
             * https://github.com/apache/kafka/blob/2.5.0/generator/src/main/java/org/apache/kafka/message/ApiMessageTypeGenerator.java#L261-L267
             * The code is materialized in ApiMessageTypes class.
             */
        } else if (matcher->flexible_api) {
            /* version 1 response header (flexible API) contains list of tagged fields, last param is ignored */
            offset = dissect_kafka_tagged_fields(tvb, pinfo, kafka_tree, offset, 0);
        }

        switch (matcher->api_key) {
            case KAFKA_PRODUCE:
                offset = dissect_kafka_produce_response(tvb, pinfo, kafka_tree, offset, dissect_api_version);
                break;
            case KAFKA_FETCH:
                offset = dissect_kafka_fetch_response(tvb, pinfo, kafka_tree, offset, dissect_api_version);
                break;
            case KAFKA_OFFSETS:
                offset = dissect_kafka_offsets_response(tvb, pinfo, kafka_tree, offset, dissect_api_version);
                break;
            case KAFKA_METADATA:
                offset = dissect_kafka_metadata_response(tvb, pinfo, kafka_tree, offset, dissect_api_version);
                break;
            case KAFKA_LEADER_AND_ISR:
                offset = dissect_kafka_leader_and_isr_response(tvb, pinfo, kafka_tree, offset, dissect_api_version);
                break;
            case KAFKA_STOP_REPLICA:
                offset = dissect_kafka_stop_replica_response(tvb, pinfo, kafka_tree, offset, dissect_api_version);
                break;
            case KAFKA_UPDATE_METADATA:
                offset = dissect_kafka_update_metadata_response(tvb, pinfo, kafka_tree, offset, dissect_api_version);
                break;
            case KAFKA_CONTROLLED_SHUTDOWN:
                offset = dissect_kafka_controlled_shutdown_response(tvb, pinfo, kafka_tree, offset, dissect_api_version);
                break;
            case KAFKA_OFFSET_COMMIT:
                offset = dissect_kafka_offset_commit_response(tvb, pinfo, kafka_tree, offset, dissect_api_version);
                break;
            case KAFKA_OFFSET_FETCH:
                offset = dissect_kafka_offset_fetch_response(tvb, pinfo, kafka_tree, offset, dissect_api_version);
                break;
            case KAFKA_FIND_COORDINATOR:
                offset = dissect_kafka_find_coordinator_response(tvb, pinfo, kafka_tree, offset, dissect_api_version);
                break;
            case KAFKA_JOIN_GROUP:
                offset = dissect_kafka_join_group_response(tvb, pinfo, kafka_tree, offset, dissect_api_version);
                break;
            case KAFKA_HEARTBEAT:
                offset = dissect_kafka_heartbeat_response(tvb, pinfo, kafka_tree, offset, dissect_api_version);
                break;
            case KAFKA_LEAVE_GROUP:
                offset = dissect_kafka_leave_group_response(tvb, pinfo, kafka_tree, offset, dissect_api_version);
                break;
            case KAFKA_SYNC_GROUP:
                offset = dissect_kafka_sync_group_response(tvb, pinfo, kafka_tree, offset, dissect_api_version);
                break;
            case KAFKA_DESCRIBE_GROUPS:
                offset = dissect_kafka_describe_groups_response(tvb, pinfo, kafka_tree, offset, dissect_api_version);
                break;
            case KAFKA_LIST_GROUPS:
                offset = dissect_kafka_list_groups_response(tvb, pinfo, kafka_tree, offset, dissect_api_version);
                break;
            case KAFKA_SASL_HANDSHAKE:
                offset = dissect_kafka_sasl_handshake_response(tvb, pinfo, kafka_tree, offset, dissect_api_version);
                break;
            case KAFKA_API_VERSIONS:
                offset = dissect_kafka_api_versions_response(tvb, pinfo, kafka_tree, offset, dissect_api_version);
                break;
            case KAFKA_CREATE_TOPICS:
                offset = dissect_kafka_create_topics_response(tvb, pinfo, kafka_tree, offset, dissect_api_version);
                break;
            case KAFKA_DELETE_TOPICS:
                offset = dissect_kafka_delete_topics_response(tvb, pinfo, kafka_tree, offset, dissect_api_version);
                break;
            case KAFKA_DELETE_RECORDS:
                offset = dissect_kafka_delete_records_response(tvb, pinfo, kafka_tree, offset, dissect_api_version);
                break;
            case KAFKA_INIT_PRODUCER_ID:
                offset = dissect_kafka_init_producer_id_response(tvb, pinfo, kafka_tree, offset, dissect_api_version);
                break;
            case KAFKA_OFFSET_FOR_LEADER_EPOCH:
                offset = dissect_kafka_offset_for_leader_epoch_response(tvb, pinfo, kafka_tree, offset, dissect_api_version);
                break;
            case KAFKA_ADD_PARTITIONS_TO_TXN:
                offset = dissect_kafka_add_partitions_to_txn_response(tvb, pinfo, kafka_tree, offset, dissect_api_version);
                break;
            case KAFKA_ADD_OFFSETS_TO_TXN:
                offset = dissect_kafka_add_offsets_to_txn_response(tvb, pinfo, kafka_tree, offset, dissect_api_version);
                break;
            case KAFKA_END_TXN:
                offset = dissect_kafka_end_txn_response(tvb, pinfo, kafka_tree, offset, dissect_api_version);
                break;
            case KAFKA_WRITE_TXN_MARKERS:
                offset = dissect_kafka_write_txn_markers_response(tvb, pinfo, kafka_tree, offset, dissect_api_version);
                break;
            case KAFKA_TXN_OFFSET_COMMIT:
                offset = dissect_kafka_txn_offset_commit_response(tvb, pinfo, kafka_tree, offset, dissect_api_version);
                break;
            case KAFKA_DESCRIBE_ACLS:
                offset = dissect_kafka_describe_acls_response(tvb, pinfo, kafka_tree, offset, dissect_api_version);
                break;
            case KAFKA_CREATE_ACLS:
                offset = dissect_kafka_create_acls_response(tvb, pinfo, kafka_tree, offset, dissect_api_version);
                break;
            case KAFKA_DELETE_ACLS:
                offset = dissect_kafka_delete_acls_response(tvb, pinfo, kafka_tree, offset, dissect_api_version);
                break;
            case KAFKA_DESCRIBE_CONFIGS:
                offset = dissect_kafka_describe_configs_response(tvb, pinfo, kafka_tree, offset, dissect_api_version);
                break;
            case KAFKA_ALTER_CONFIGS:
                offset = dissect_kafka_alter_configs_response(tvb, pinfo, kafka_tree, offset, dissect_api_version);
                break;
            case KAFKA_ALTER_REPLICA_LOG_DIRS:
                offset = dissect_kafka_alter_replica_log_dirs_response(tvb, pinfo, kafka_tree, offset, dissect_api_version);
                break;
            case KAFKA_DESCRIBE_LOG_DIRS:
                offset = dissect_kafka_describe_log_dirs_response(tvb, pinfo, kafka_tree, offset, dissect_api_version);
                break;
            case KAFKA_CREATE_PARTITIONS:
                offset = dissect_kafka_create_partitions_response(tvb, pinfo, kafka_tree, offset, dissect_api_version);
                break;
            case KAFKA_SASL_AUTHENTICATE:
                offset = dissect_kafka_sasl_authenticate_response(tvb, pinfo, kafka_tree, offset, dissect_api_version);
                break;
            case KAFKA_CREATE_DELEGATION_TOKEN:
                offset = dissect_kafka_create_delegation_token_response(tvb, pinfo, kafka_tree, offset, dissect_api_version);
                break;
            case KAFKA_RENEW_DELEGATION_TOKEN:
                offset = dissect_kafka_renew_delegation_token_response(tvb, pinfo, kafka_tree, offset, dissect_api_version);
                break;
            case KAFKA_EXPIRE_DELEGATION_TOKEN:
                offset = dissect_kafka_expire_delegation_token_response(tvb, pinfo, kafka_tree, offset, dissect_api_version);
                break;
            case KAFKA_DESCRIBE_DELEGATION_TOKEN:
                offset = dissect_kafka_describe_delegation_token_response(tvb, pinfo, kafka_tree, offset, dissect_api_version);
                break;
            case KAFKA_DELETE_GROUPS:
                offset = dissect_kafka_delete_groups_response(tvb, pinfo, kafka_tree, offset, dissect_api_version);
                break;
            case KAFKA_ELECT_LEADERS:
                offset = dissect_kafka_elect_leaders_response(tvb, pinfo, kafka_tree, offset, dissect_api_version);
                break;
            case KAFKA_INC_ALTER_CONFIGS:
                offset = dissect_kafka_inc_alter_configs_response(tvb, pinfo, kafka_tree, offset, dissect_api_version);
                break;
            case KAFKA_ALTER_PARTITION_REASSIGNMENTS:
                offset = dissect_kafka_alter_partition_reassignments_response(tvb, pinfo, kafka_tree, offset, dissect_api_version);
                break;
            case KAFKA_LIST_PARTITION_REASSIGNMENTS:
                offset = dissect_kafka_list_partition_reassignments_response(tvb, pinfo, kafka_tree, offset, dissect_api_version);
                break;
            case KAFKA_OFFSET_DELETE:
                offset = dissect_kafka_offset_delete_response(tvb, pinfo, kafka_tree, offset, dissect_api_version);
                break;
            case KAFKA_DESCRIBE_CLUSTER:
                offset = dissect_kafka_describe_cluster_response(tvb, pinfo, kafka_tree, offset, dissect_api_version);
                break;
            case KAFKA_ALLOCATE_PRODUCER_IDS:
                offset = dissect_kafka_allocate_producer_ids_response(tvb, pinfo, kafka_tree, offset, dissect_api_version);
                break;
        }

    }

    if (offset != (int)pdu_length + 4) {
        expert_add_info(pinfo, root_ti, &ei_kafka_pdu_length_mismatch);
    }

    return offset;
}

/*
 * Compute the length of a Kafka protocol frame (PDU) from the minimal fragment.
 * The datastream in TCP (and TLS) is and abstraction of continuous stream of octets.
 * On the network level these are transported in chunks (packets). On the application
 * protocol level we do also deal with discrete chunks (PDUs). Ideally these should
 * match. In the real life the boundaries are different. In Kafka case a PDU may span
 * multiple network packets. A PDU starts with 32 bit unsigned integer that specifies
 * remaining protocol frame length. Fortunatelly protocol implementations execute
 * flush between subsequent PDUs, therefore we should not expect PDU starting in the middle
 * of TCP data packet or TLS data frame.
 */
static unsigned
get_kafka_pdu_len(packet_info *pinfo _U_, tvbuff_t *tvb, int offset, void *data _U_)
{
    return 4 + tvb_get_ntohl(tvb, offset);
}

/*
 * Attempt to dissect Kafka protocol frames.
 */
static int
dissect_kafka_tcp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
    tcp_dissect_pdus(tvb, pinfo, tree, true, 4,
            get_kafka_pdu_len, dissect_kafka, data);
    return tvb_captured_length(tvb);
}

static void
compute_kafka_api_names(void)
{
    unsigned i;
    unsigned len = array_length(kafka_apis);

    for (i = 0; i < len; ++i) {
        kafka_api_names[i].value  = kafka_apis[i].api_key;
        kafka_api_names[i].strptr = kafka_apis[i].name;
    }

    kafka_api_names[len].value  = 0;
    kafka_api_names[len].strptr = NULL;
}

static void
proto_register_kafka_protocol_fields(int protocol)
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
        { &hf_kafka_log_start_offset,
            { "Log Start Offset", "kafka.log_start_offset",
               FT_INT64, BASE_DEC, 0, 0,
               NULL, HFILL }
        },
        { &hf_kafka_last_stable_offset,
            { "Last Stable Offset", "kafka.last_stable_offset",
               FT_INT64, BASE_DEC, 0, 0,
               NULL, HFILL }
        },
        { &hf_kafka_first_offset,
            { "First Offset", "kafka.first_offset",
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
        { &hf_kafka_error_message,
            { "Error Message", "kafka.error_message",
               FT_STRING, BASE_NONE, 0, 0,
               NULL, HFILL }
        },
        { &hf_kafka_api_key,
            { "API Key", "kafka.api_key",
                FT_INT16, BASE_DEC, VALS(kafka_api_names), 0,
                "Request API Key.", HFILL }
        },
        { &hf_kafka_api_version,
            { "API Version", "kafka.api_version",
                FT_INT16, BASE_DEC, 0, 0,
                "Request API Version.", HFILL }
        },
        // these should be deprecated
        // --- begin ---
        { &hf_kafka_request_api_key,
            { "API Key", "kafka.request_key",
               FT_INT16, BASE_DEC, VALS(kafka_api_names), 0,
              "Request API.", HFILL }
        },
        { &hf_kafka_response_api_key,
            { "API Key", "kafka.response_key",
               FT_INT16, BASE_DEC, VALS(kafka_api_names), 0,
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
        // --- end ---
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
        { &hf_kafka_client_host,
            { "Client Host", "kafka.client_host",
               FT_STRING, BASE_NONE, 0, 0,
               NULL, HFILL }
        },
        { &hf_kafka_transactional_id,
            { "Transactional ID", "kafka.transactional_id",
               FT_STRING, BASE_NONE, 0, 0,
               NULL, HFILL }
        },
        { &hf_kafka_transaction_result,
            { "Transaction Result", "kafka.transaction_result",
               FT_INT8, BASE_DEC, VALS(kafka_transaction_results), 0,
               NULL, HFILL }
        },
        { &hf_kafka_transaction_timeout,
            { "Transaction Timeout", "kafka.transaction_timeout",
               FT_INT32, BASE_DEC, 0, 0,
               NULL, HFILL }
        },
        { &hf_kafka_required_acks,
            { "Required Acks", "kafka.required_acks",
               FT_INT16, BASE_DEC, VALS(kafka_acks), 0,
               NULL, HFILL }
        },
        { &hf_kafka_timeout,
            { "Timeout", "kafka.timeout",
               FT_INT32, BASE_DEC, 0, 0,
               NULL, HFILL }
        },
        { &hf_kafka_topic_id,
            { "Topic ID", "kafka.topic_id",
              FT_GUID, BASE_NONE, 0, 0,
              NULL, HFILL }
        },
        { &hf_kafka_topic_name,
            { "Topic Name", "kafka.topic_name",
               FT_STRING, BASE_NONE, 0, 0,
               NULL, HFILL }
        },
        { &hf_kafka_producer_id,
            { "Producer ID", "kafka.producer_id",
               FT_INT64, BASE_DEC, 0, 0,
               NULL, HFILL }
        },
        { &hf_kafka_producer_epoch,
            { "Producer Epoch", "kafka.producer_epoch",
                FT_INT16, BASE_DEC, 0, 0,
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
        { &hf_kafka_replication_factor,
            { "Replication Factor", "kafka.replication_factor",
               FT_INT16, BASE_DEC, 0, 0,
               NULL, HFILL }
        },
        { &hf_kafka_isr,
            { "Caught-Up Replica ID", "kafka.isr_id",
               FT_INT32, BASE_DEC, 0, 0,
               NULL, HFILL }
        },
        { &hf_kafka_offline,
            { "Offline Replica ID", "kafka.offline_id",
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
               FT_UINT8, BASE_DEC, VALS(kafka_message_codecs), KAFKA_MESSAGE_CODEC_MASK,
               NULL, HFILL }
        },
        { &hf_kafka_message_timestamp_type,
            { "Timestamp Type", "kafka.message_timestamp_type",
               FT_UINT8, BASE_DEC, VALS(kafka_message_timestamp_types), KAFKA_MESSAGE_TIMESTAMP_MASK,
               NULL, HFILL }
        },
        { &hf_kafka_batch_crc,
            { "CRC32", "kafka.batch_crc",
                FT_UINT32, BASE_HEX, 0, 0,
                NULL, HFILL }
        },
        { &hf_kafka_batch_codec,
            { "Compression Codec", "kafka.batch_codec",
                FT_UINT16, BASE_DEC, VALS(kafka_message_codecs), KAFKA_MESSAGE_CODEC_MASK,
                NULL, HFILL }
        },
        { &hf_kafka_batch_timestamp_type,
            { "Timestamp Type", "kafka.batch_timestamp_type",
                FT_UINT16, BASE_DEC, VALS(kafka_message_timestamp_types), KAFKA_MESSAGE_TIMESTAMP_MASK,
                NULL, HFILL }
        },
        { &hf_kafka_batch_transactional,
            { "Transactional", "kafka.batch_transactional",
                FT_UINT16, BASE_DEC, VALS(kafka_batch_transactional_values), KAFKA_BATCH_TRANSACTIONAL_MASK,
                NULL, HFILL }
        },
        { &hf_kafka_batch_control_batch,
            { "Control Batch", "kafka.batch_control_batch",
                FT_UINT16, BASE_DEC, VALS(kafka_batch_control_batch_values), KAFKA_BATCH_CONTROL_BATCH_MASK,
                NULL, HFILL }
        },
        { &hf_kafka_batch_last_offset_delta,
            { "Last Offset Delta", "kafka.batch_last_offset_delta",
               FT_UINT32, BASE_DEC, 0, 0,
               NULL, HFILL }
        },
        { &hf_kafka_batch_first_timestamp,
            { "First Timestamp", "kafka.batch_first_timestamp",
                FT_ABSOLUTE_TIME, ABSOLUTE_TIME_UTC, NULL, 0,
                NULL, HFILL }
        },
        { &hf_kafka_batch_last_timestamp,
            { "Last Timestamp", "kafka.batch_last_timestamp",
                FT_ABSOLUTE_TIME, ABSOLUTE_TIME_UTC, NULL, 0,
                NULL, HFILL }
        },
        { &hf_kafka_batch_base_sequence,
            { "Base Sequence", "kafka.batch_base_sequence",
                FT_INT32, BASE_DEC, 0, 0,
                NULL, HFILL }
        },
        { &hf_kafka_batch_size,
            { "Size", "kafka.batch_size",
                FT_UINT32, BASE_DEC, 0, 0,
                NULL, HFILL }
        },
        { &hf_kafka_batch_index,
            { "Batch Index", "kafka.batch_index",
                FT_UINT32, BASE_DEC, 0, 0,
                NULL, HFILL }
        },
        { &hf_kafka_batch_index_error_message,
            { "Batch Index Error Message", "kafka.batch_index_error_message",
                FT_STRING, BASE_NONE, 0, 0,
                NULL, HFILL }
        },
        { &hf_kafka_message_timestamp,
            { "Timestamp", "kafka.message_timestamp",
               FT_ABSOLUTE_TIME, ABSOLUTE_TIME_UTC, NULL, 0,
               NULL, HFILL }
        },
        { &hf_kafka_message_key,
            { "Key", "kafka.message_key",
               FT_BYTES, BASE_SHOW_ASCII_PRINTABLE, 0, 0,
               NULL, HFILL }
        },
        { &hf_kafka_message_value,
            { "Value", "kafka.message_value",
               FT_BYTES, BASE_SHOW_ASCII_PRINTABLE, 0, 0,
               NULL, HFILL }
        },
        { &hf_kafka_message_compression_reduction,
            { "Compression Reduction (compressed/uncompressed)", "kafka.message_compression_reduction",
               FT_FLOAT, BASE_NONE, 0, 0,
               NULL, HFILL }
        },
        { &hf_kafka_truncated_content,
            { "Truncated Content", "kafka.truncated_content",
               FT_BYTES, BASE_NONE, 0, 0,
               NULL, HFILL }
        },
        { &hf_kafka_consumer_group,
            { "Consumer Group", "kafka.consumer_group",
               FT_STRING, BASE_NONE, 0, 0,
               NULL, HFILL }
        },
        { &hf_kafka_consumer_group_instance,
            { "Consumer Group Instance", "kafka.consumer_group_instance",
               FT_STRING, BASE_NONE, 0, 0,
               NULL, HFILL }
        },
        { &hf_kafka_coordinator_key,
            { "Coordinator Key", "kafka.coordinator_key",
               FT_STRING, BASE_NONE, 0, 0,
               NULL, HFILL }
        },
        { &hf_kafka_coordinator_type,
            { "Coordinator Type", "kafka.coordinator_type",
               FT_INT8, BASE_DEC, VALS(kafka_coordinator_types), 0,
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
        { &hf_kafka_broker_epoch,
            { "Broker Epoch", "kafka.broker_epoch",
               FT_INT64, BASE_DEC, 0, 0,
               NULL, HFILL }
        },
        { &hf_kafka_broker_host,
            { "Host", "kafka.host",
               FT_STRING, BASE_NONE, 0, 0,
               NULL, HFILL }
        },
        { &hf_kafka_listener_name,
            { "Listener", "kafka.listener_name",
               FT_STRING, BASE_NONE, 0, 0,
               NULL, HFILL }
        },
        { &hf_kafka_broker_port,
            { "Port", "kafka.port",
               FT_INT32, BASE_DEC, 0, 0,
               NULL, HFILL }
        },
        { &hf_kafka_rack,
            { "Rack", "kafka.rack",
               FT_STRING, BASE_NONE, 0, 0,
               NULL, HFILL }
        },
        { &hf_kafka_broker_security_protocol_type,
            { "Security Protocol Type", "kafka.broker_security_protocol_type",
               FT_INT16, BASE_DEC, VALS(kafka_security_protocol_types), 0,
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
        { &hf_kafka_controller_epoch,
            { "Controller Epoch", "kafka.controller_epoch",
               FT_INT32, BASE_DEC, 0, 0,
               NULL, HFILL }
        },
        { &hf_kafka_delete_partitions,
            { "Delete Partitions", "kafka.delete_partitions",
               FT_BOOLEAN, BASE_NONE, 0, 0,
               NULL, HFILL }
        },
        { &hf_kafka_group_leader_id,
            { "Leader ID", "kafka.group_leader_id",
               FT_STRING, BASE_NONE, 0, 0,
               NULL, HFILL }
        },
        { &hf_kafka_leader_id,
            { "Leader ID", "kafka.leader_id",
               FT_INT32, BASE_DEC, 0, 0,
               NULL, HFILL }
        },
        { &hf_kafka_leader_epoch,
            { "Leader Epoch", "kafka.leader_epoch",
               FT_INT32, BASE_DEC, 0, 0,
               NULL, HFILL }
        },
        { &hf_kafka_current_leader_epoch,
            { "Leader Epoch", "kafka.current_leader_epoch",
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
        { &hf_kafka_isolation_level,
            { "Isolation Level", "kafka.isolation_level",
               FT_INT8, BASE_DEC, VALS(kafka_isolation_levels), 0,
               NULL, HFILL }
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
            { "Response Frame", "kafka.response_frame",
               FT_FRAMENUM, BASE_NONE, FRAMENUM_TYPE(FT_FRAMENUM_RESPONSE), 0,
               NULL, HFILL }
        },
        { &hf_kafka_api_versions_api_key,
            { "API Key", "kafka.api_versions.api_key",
               FT_INT16, BASE_DEC, VALS(kafka_api_names), 0,
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
        },
        { &hf_kafka_session_timeout,
            { "Session Timeout", "kafka.session_timeout",
               FT_INT32, BASE_DEC, 0, 0,
               NULL, HFILL }
        },
        { &hf_kafka_rebalance_timeout,
            { "Rebalance Timeout", "kafka.rebalance_timeout",
               FT_INT32, BASE_DEC, 0, 0,
               NULL, HFILL }
        },
        { &hf_kafka_group_state,
            { "State", "kafka.group_state",
               FT_STRING, BASE_NONE, 0, 0,
               NULL, HFILL }
        },
        { &hf_kafka_member_id,
            { "Consumer Group Member ID", "kafka.member_id",
               FT_STRING, BASE_NONE, 0, 0,
               NULL, HFILL }
        },
        { &hf_kafka_protocol_type,
            { "Protocol Type", "kafka.protocol_type",
               FT_STRING, BASE_NONE, 0, 0,
               NULL, HFILL }
        },
        { &hf_kafka_protocol_name,
            { "Protocol Name", "kafka.protocol_name",
               FT_STRING, BASE_NONE, 0, 0,
               NULL, HFILL }
        },
        { &hf_kafka_protocol_metadata,
            { "Protocol Metadata", "kafka.protocol_metadata",
               FT_BYTES, BASE_NONE, 0, 0,
               NULL, HFILL }
        },
        { &hf_kafka_member_metadata,
            { "Member Metadata", "kafka.member_metadata",
               FT_BYTES, BASE_NONE, 0, 0,
               NULL, HFILL }
        },
        { &hf_kafka_generation_id,
            { "Generation ID", "kafka.generation_id",
               FT_INT32, BASE_DEC, 0, 0,
               NULL, HFILL }
        },
        { &hf_kafka_member_assignment,
            { "Member Assignment", "kafka.member_assignment",
               FT_BYTES, BASE_NONE, 0, 0,
               NULL, HFILL }
        },
        { &hf_kafka_sasl_mechanism,
            { "SASL Mechanism", "kafka.sasl_mechanism",
               FT_STRING, BASE_NONE, 0, 0,
               NULL, HFILL }
        },
        { &hf_kafka_num_partitions,
            { "Number of Partitions", "kafka.num_partitions",
               FT_INT32, BASE_DEC, 0, 0,
               NULL, HFILL }
        },
        { &hf_kafka_zk_version,
            { "Zookeeper Version", "kafka.zk_version",
               FT_INT32, BASE_DEC, 0, 0,
               NULL, HFILL }
        },
        { &hf_kafka_is_new_replica,
            { "New Replica", "kafka.is_new_replica",
                FT_BOOLEAN, BASE_NONE, 0, 0,
                NULL, HFILL }
        },
        { &hf_kafka_leader_recovery_state,
            { "Leader Recovery State", "kafka.leader_recovery_state",
                FT_INT8, BASE_DEC, 0, 0,
                NULL, HFILL }
        },
        { &hf_kafka_config_key,
            { "Key", "kafka.config_key",
               FT_STRING, BASE_NONE, 0, 0,
               NULL, HFILL }
        },
        { &hf_kafka_config_value,
            { "Value", "kafka.config_value",
               FT_STRING, BASE_NONE, 0, 0,
               NULL, HFILL }
        },
        { &hf_kafka_config_operation,
            { "Operation", "kafka.config_operation",
               FT_INT8, BASE_DEC, VALS(config_operations), 0,
               NULL, HFILL }
        },
        { &hf_kafka_commit_timestamp,
            { "Timestamp", "kafka.commit_timestamp",
               FT_ABSOLUTE_TIME, ABSOLUTE_TIME_UTC, NULL, 0,
               NULL, HFILL }
        },
        { &hf_kafka_retention_time,
            { "Retention Time", "kafka.retention_time",
               FT_INT64, BASE_DEC, 0, 0,
               NULL, HFILL }
        },
        { &hf_kafka_forgotten_topic_name,
            { "Forgotten Topic Name", "kafka.forgotten_topic_name",
                FT_STRING, BASE_NONE, 0, 0,
                NULL, HFILL }
        },
        { &hf_kafka_forgotten_topic_id,
            { "Forgotten Topic ID", "kafka.forgotten_topic_id",
                FT_GUID, BASE_NONE, 0, 0,
                NULL, HFILL }
        },
        { &hf_kafka_forgotten_topic_partition,
            { "Forgotten Topic Partition", "kafka.forgotten_topic_partition",
                FT_INT64, BASE_DEC, 0, 0,
                NULL, HFILL }
        },
        { &hf_kafka_fetch_session_id,
            { "Fetch Session ID", "kafka.fetch_session_id",
                FT_INT64, BASE_DEC, 0, 0,
                NULL, HFILL }
        },
        { &hf_kafka_fetch_session_epoch,
            { "Fetch Session Epoch", "kafka.fetch_session_epoch",
                FT_INT64, BASE_DEC, 0, 0,
                NULL, HFILL }
        },
        { &hf_kafka_require_stable_offset,
            { "Require Stable Offset", "kafka.require_stable_offset",
                FT_BOOLEAN, BASE_NONE, 0, 0,
                NULL, HFILL }
        },
        { &hf_kafka_record_header_key,
            { "Header Key", "kafka.header_key",
                FT_STRING, BASE_NONE, 0, 0,
                NULL, HFILL }
        },
        { &hf_kafka_record_header_value,
            { "Header Value", "kafka.header_value",
                FT_BYTES, BASE_SHOW_ASCII_PRINTABLE, 0, 0,
                NULL, HFILL }
        },
        { &hf_kafka_record_attributes,
            { "Record Attributes (reserved)", "kafka.record_attributes",
                FT_INT8, BASE_DEC, 0, 0,
                NULL, HFILL }
        },
        { &hf_kafka_allow_auto_topic_creation,
            { "Allow Auto Topic Creation", "kafka.allow_auto_topic_creation",
                FT_BOOLEAN, BASE_NONE, 0, 0,
                NULL, HFILL }
        },
        { &hf_kafka_validate_only,
            { "Only Validate the Request", "kafka.validate_only",
                FT_BOOLEAN, BASE_NONE, 0, 0,
                NULL, HFILL }
        },
        { &hf_kafka_coordinator_epoch,
            { "Coordinator Epoch", "kafka.coordinator_epoch",
                FT_INT32, BASE_DEC, 0, 0,
                NULL, HFILL }
        },
        { &hf_kafka_sasl_auth_bytes,
            { "SASL Authentication Bytes", "kafka.sasl_authentication",
                FT_BYTES, BASE_NONE, 0, 0,
                NULL, HFILL }
        },
        { &hf_kafka_session_lifetime_ms,
            { "Session Lifetime (ms)", "kafka.session_lifetime_ms",
                FT_INT64, BASE_DEC, 0, 0,
                NULL, HFILL }
        },
        { &hf_kafka_acl_resource_type,
            { "Resource Type", "kafka.acl_resource_type",
                FT_INT8, BASE_DEC, VALS(acl_resource_types), 0,
                NULL, HFILL }
        },
        { &hf_kafka_acl_resource_name,
            { "Resource Name", "kafka.acl_resource_name",
                FT_STRING, BASE_NONE, 0, 0,
                NULL, HFILL }
        },
        { &hf_kafka_acl_resource_pattern_type,
            { "Resource Pattern Type", "kafka.acl_resource_pattern_type",
                FT_INT8, BASE_DEC, VALS(acl_resource_pattern_types), 0,
                NULL, HFILL }
        },
        { &hf_kafka_acl_principal,
            { "Principal", "kafka.acl_principal",
                FT_STRING, BASE_NONE, 0, 0,
                NULL, HFILL }
        },
        { &hf_kafka_acl_host,
            { "Host", "kafka.acl_host",
                FT_STRING, BASE_NONE, 0, 0,
                NULL, HFILL }
        },
        { &hf_kafka_acl_operation,
            { "Operation", "kafka.acl_operation",
                FT_INT8, BASE_DEC, VALS(acl_operations), 0,
                NULL, HFILL }
        },
        { &hf_kafka_acl_permission_type,
            { "Permission Type", "kafka.acl_permission_type",
                FT_INT8, BASE_DEC, VALS(acl_permission_types), 0,
                NULL, HFILL }
        },
        { &hf_kafka_config_resource_type,
            { "Resource Type", "kafka.config_resource_type",
                FT_INT8, BASE_DEC, VALS(config_resource_types), 0,
                NULL, HFILL }
        },
        { &hf_kafka_config_resource_name,
            { "Resource Name", "kafka.config_resource_name",
                FT_STRING, BASE_NONE, 0, 0,
                NULL, HFILL }
        },
        { &hf_kafka_config_include_synonyms,
            { "Include Synonyms", "kafka.config_include_synonyms",
                FT_BOOLEAN, BASE_NONE, 0, 0,
                NULL, HFILL }
        },
        { &hf_kafka_config_include_documentation,
            { "Include Documentation", "kafka.config_include_documentation",
                FT_BOOLEAN, BASE_NONE, 0, 0,
                NULL, HFILL }
        },
        { &hf_kafka_config_default,
            { "Default", "kafka.config_default",
                FT_BOOLEAN, BASE_NONE, 0, 0,
                NULL, HFILL }
        },
        { &hf_kafka_config_readonly,
            { "Readonly", "kafka.config_readonly",
                FT_BOOLEAN, BASE_NONE, 0, 0,
                NULL, HFILL }
        },
        { &hf_kafka_config_sensitive,
            { "Sensitive", "kafka.config_sensitive",
                FT_BOOLEAN, BASE_NONE, 0, 0,
                NULL, HFILL }
        },
        { &hf_kafka_config_data_type,
            { "Data Type", "kafka.config_data_type",
                FT_INT8, BASE_DEC, 0, 0,
                NULL, HFILL }
        },
        { &hf_kafka_config_documentation,
            { "Documentation", "kafka.config_documentation",
                FT_STRING, BASE_NONE, 0, 0,
                NULL, HFILL }
        },
        { &hf_kafka_config_source,
            { "Source", "kafka.config_source",
                FT_INT8, BASE_DEC, VALS(config_sources), 0,
                NULL, HFILL }
        },
        { &hf_kafka_log_dir,
            { "Log Directory", "kafka.log_dir",
                FT_STRING, BASE_NONE, 0, 0,
                NULL, HFILL }
        },
        { &hf_kafka_segment_size,
            { "Segment Size", "kafka.segment_size",
                FT_UINT64, BASE_DEC, 0, 0,
                NULL, HFILL }
        },
        { &hf_kafka_offset_lag,
            { "Offset Lag", "kafka.offset_lag",
                FT_UINT64, BASE_DEC, 0, 0,
                NULL, HFILL }
        },
        { &hf_kafka_future,
            { "Future", "kafka.future",
                FT_BOOLEAN, BASE_NONE, 0, 0,
                NULL, HFILL }
        },
        { &hf_kafka_partition_count,
            { "Partition Count", "kafka.partition_count",
                FT_UINT32, BASE_DEC, 0, 0,
                NULL, HFILL }
        },
        { &hf_kafka_token_max_life_time,
            { "Max Life Time", "kafka.token_max_life_time",
                FT_INT64, BASE_DEC, 0, 0,
                NULL, HFILL }
        },
        { &hf_kafka_token_renew_time,
            { "Renew Time", "kafka.renew_time",
                FT_INT64, BASE_DEC, 0, 0,
                NULL, HFILL }
        },
        { &hf_kafka_token_expiry_time,
            { "Expiry Time", "kafka.expiry_time",
                FT_INT64, BASE_DEC, 0, 0,
                NULL, HFILL }
        },
        { &hf_kafka_token_principal_type,
            { "Principal Type", "kafka.principal_type",
                FT_STRING, BASE_NONE, 0, 0,
                NULL, HFILL }
        },
        { &hf_kafka_token_principal_name,
            { "Principal Name", "kafka.principal_name",
                FT_STRING, BASE_NONE, 0, 0,
                NULL, HFILL }
        },
        { &hf_kafka_token_issue_timestamp,
            { "Issue Timestamp", "kafka.token_issue_timestamp",
                FT_ABSOLUTE_TIME, ABSOLUTE_TIME_UTC, NULL, 0,
                NULL, HFILL }
        },
        { &hf_kafka_token_expiry_timestamp,
            { "Expiry Timestamp", "kafka.token_expiry_timestamp",
                FT_ABSOLUTE_TIME, ABSOLUTE_TIME_UTC, NULL, 0,
                NULL, HFILL }
        },
        { &hf_kafka_token_max_timestamp,
            { "Max Timestamp", "kafka.token_max_timestamp",
                FT_ABSOLUTE_TIME, ABSOLUTE_TIME_UTC, NULL, 0,
                NULL, HFILL }
        },
        { &hf_kafka_token_id,
            { "ID", "kafka.token_id",
                FT_STRING, BASE_NONE, 0, 0,
                NULL, HFILL }
        },
        { &hf_kafka_token_hmac,
            { "HMAC", "kafka.token_hmac",
                FT_BYTES, BASE_NONE, 0, 0,
                NULL, HFILL }
        },
        { &hf_kafka_include_cluster_authorized_ops,
            { "Include Cluster Authorized Operations", "kafka.include_cluster_authorized_ops",
                FT_BOOLEAN, BASE_NONE, 0, 0,
                NULL, HFILL }
        },
        { &hf_kafka_include_topic_authorized_ops,
            { "Include Topic Authorized Operations", "kafka.include_topic_authorized_ops",
                FT_BOOLEAN, BASE_NONE, 0, 0,
                NULL, HFILL }
        },
        { &hf_kafka_cluster_authorized_ops,
            { "Cluster Authorized Operations", "kafka.cluster_authorized_ops",
                FT_UINT32, BASE_HEX, 0, 0,
                NULL, HFILL }
        },
        { &hf_kafka_topic_authorized_ops,
            { "Topic Authorized Operations", "kafka.topic_authorized_ops",
                FT_UINT32, BASE_HEX, 0, 0,
                NULL, HFILL }
        },
        { &hf_kafka_include_group_authorized_ops,
            { "Include Group Authorized Operations", "kafka.include_group_authorized_ops",
                FT_BOOLEAN, BASE_NONE, 0, 0,
                NULL, HFILL }
        },
        { &hf_kafka_group_authorized_ops,
            { "Group Authorized Operations", "kafka.group_authorized_ops",
                FT_UINT32, BASE_HEX, 0, 0,
                NULL, HFILL }
        },
        { &hf_kafka_election_type,
            { "Election Type", "kafka.election_type",
                FT_INT8, BASE_DEC, VALS(election_types), 0,
                NULL, HFILL }
        },
        { &hf_kafka_tagged_field_tag,
            { "Tag Value", "kafka.tagged_field_tag",
                FT_UINT64, BASE_HEX, 0, 0,
                NULL, HFILL }
        },
        { &hf_kafka_tagged_field_data,
            { "Tag Data", "kafka.tagged_field_data",
                FT_BYTES, BASE_SHOW_ASCII_PRINTABLE, 0, 0,
                NULL, HFILL }
        },
        { &hf_kafka_client_software_name,
            { "Client Software Name", "kafka.client_software_name",
                FT_STRING, BASE_NONE, 0, 0,
                NULL, HFILL }
        },
        { &hf_kafka_client_software_version,
            { "Client Software Version", "kafka.client_software_version",
                FT_STRING, BASE_NONE, 0, 0,
                NULL, HFILL }
        },
        { &hf_kafka_is_kraft_controller,
            { "Is KRaft Controller", "kafka.is_kraft_controller",
              FT_BOOLEAN, BASE_NONE, 0, 0,
              NULL, HFILL }
        },
        { &hf_kafka_topic_inclusion_type,
            { "Topic Inclusion Type", "kafka.topic_inclusion_type",
              FT_INT8, BASE_DEC, 0, 0,
              NULL, HFILL }
        },
        { &hf_kafka_delete_partition,
            { "Delete Partition", "kafka.delete_partition",
              FT_BOOLEAN, BASE_NONE, 0, 0,
              NULL, HFILL }
        },
        { &hf_kafka_join_reason,
            { "(Re)Join Reason", "kafka.join_reason",
              FT_STRING, BASE_NONE, 0, 0,
              NULL, HFILL }
        },
        { &hf_kafka_leave_reason,
            { "Leave Reason", "kafka.leave_reason",
              FT_STRING, BASE_NONE, 0, 0,
              NULL, HFILL }
        },
        { &hf_kafka_skip_assignment,
            { "Skip Assignment", "kafka.skip_assignment",
              FT_BOOLEAN, BASE_NONE, 0, 0,
              NULL, HFILL }
        },
        { &hf_kafka_producer_id_start,
            { "First Producer ID", "kafka.producer_id_start",
              FT_INT64, BASE_DEC, 0, 0,
              NULL, HFILL }
        },
        { &hf_kafka_producer_id_len,
            { "Number of Producers", "kafka.producer_len",
              FT_INT32, BASE_DEC, 0, 0,
              NULL, HFILL }
        },
        { &hf_kafka_group_id,
            { "Group ID", "kafka.group_id",
              FT_STRING, BASE_NONE, 0, 0,
              NULL, HFILL }
        },
        { &hf_kafka_member_epoch,
            { "Member Epoch", "kafka.member_epoch",
              FT_INT32, BASE_DEC, 0, 0,
              NULL, HFILL }
        },
        { &hf_kafka_endpoint_type,
            { "Endpoint Type", "kafka.endpoint_type",
              FT_INT8, BASE_DEC, 0, 0,
              NULL, HFILL }
        },
        { &hf_kafka_last_fetched_epoch,
            { "Last Fetched Epoch", "kafka.last_fetched_epoch",
              FT_INT32, BASE_DEC, 0, 0,
              NULL, HFILL }
        },
    };

    proto_register_field_array(protocol, hf, array_length(hf));

}

static void
proto_register_kafka_protocol_subtrees(const int proto _U_)
{
    static int *ett[] = {
        &ett_kafka,
        &ett_kafka_batch,
        &ett_kafka_message,
        &ett_kafka_message_set,
        &ett_kafka_offline,
        &ett_kafka_isrs,
        &ett_kafka_replicas,
        &ett_kafka_broker,
        &ett_kafka_brokers,
        &ett_kafka_broker_end_point,
        &ett_kafka_markers,
        &ett_kafka_marker,
        &ett_kafka_topics,
        &ett_kafka_topic,
        &ett_kafka_partitions,
        &ett_kafka_partition,
        &ett_kafka_api_version,
        &ett_kafka_group_protocols,
        &ett_kafka_group_protocol,
        &ett_kafka_group_members,
        &ett_kafka_group_member,
        &ett_kafka_group_assignments,
        &ett_kafka_group_assignment,
        &ett_kafka_groups,
        &ett_kafka_group,
        &ett_kafka_sasl_enabled_mechanisms,
        &ett_kafka_replica_assignment,
        &ett_kafka_configs,
        &ett_kafka_config,
        &ett_kafka_request_forgotten_topic,
        &ett_kafka_record,
        &ett_kafka_record_headers,
        &ett_kafka_record_headers_header,
        &ett_kafka_aborted_transactions,
        &ett_kafka_aborted_transaction,
        &ett_kafka_resources,
        &ett_kafka_resource,
        &ett_kafka_acls,
        &ett_kafka_acl,
        &ett_kafka_acl_creations,
        &ett_kafka_acl_creation,
        &ett_kafka_acl_filters,
        &ett_kafka_acl_filter,
        &ett_kafka_acl_filter_matches,
        &ett_kafka_acl_filter_match,
        &ett_kafka_config_synonyms,
        &ett_kafka_config_synonym,
        &ett_kafka_config_entries,
        &ett_kafka_config_entry,
        &ett_kafka_log_dirs,
        &ett_kafka_log_dir,
        &ett_kafka_renewers,
        &ett_kafka_renewer,
        &ett_kafka_owners,
        &ett_kafka_owner,
        &ett_kafka_tokens,
        &ett_kafka_token,
        &ett_kafka_tagged_fields,
        &ett_kafka_tagged_field,
        &ett_kafka_record_errors,
        &ett_kafka_record_error,
    };
    proto_register_subtree_array(ett, array_length(ett));
}

static void
proto_register_kafka_expert_module(const int proto) {
    expert_module_t* expert_kafka;
    static ei_register_info ei[] = {
            { &ei_kafka_request_missing,
                    { "kafka.request_missing", PI_UNDECODED, PI_WARN, "Request missing", EXPFILL }},
            { &ei_kafka_unknown_api_key,
                    { "kafka.unknown_api_key", PI_UNDECODED, PI_WARN, "Unknown API key", EXPFILL }},
            { &ei_kafka_unsupported_api_version,
                    { "kafka.unsupported_api_version", PI_UNDECODED, PI_WARN, "Unsupported API version", EXPFILL }},
            { &ei_kafka_assumed_api_version,
                    { "kafka.assumed_api_version", PI_ASSUMPTION, PI_WARN, "Assumed API version", EXPFILL }},
            { &ei_kafka_bad_string_length,
                    { "kafka.bad_string_length", PI_MALFORMED, PI_WARN, "Invalid string length field", EXPFILL }},
            { &ei_kafka_bad_bytes_length,
                    { "kafka.bad_bytes_length", PI_MALFORMED, PI_WARN, "Invalid byte length field", EXPFILL }},
            { &ei_kafka_bad_array_length,
                    { "kafka.bad_array_length", PI_MALFORMED, PI_WARN, "Invalid array length field", EXPFILL }},
            { &ei_kafka_bad_record_length,
                    { "kafka.bad_record_length", PI_MALFORMED, PI_WARN, "Invalid record length field", EXPFILL }},
            { &ei_kafka_bad_varint,
                    { "kafka.bad_varint", PI_MALFORMED, PI_WARN, "Invalid varint bytes", EXPFILL }},
            { &ei_kafka_bad_message_set_length,
                    { "kafka.ei_kafka_bad_message_set_length", PI_MALFORMED, PI_WARN, "Message set size does not match content", EXPFILL }},
            { &ei_kafka_bad_decompression_length,
                    { "kafka.ei_kafka_bad_decompression_length", PI_MALFORMED, PI_WARN, "Decompression size too large", EXPFILL }},
            { &ei_kafka_zero_decompression_length,
                    { "kafka.ei_kafka_zero_decompression_length", PI_PROTOCOL, PI_NOTE, "Decompression size zero", EXPFILL }},
            { &ei_kafka_unknown_message_magic,
                    { "kafka.unknown_message_magic", PI_MALFORMED, PI_WARN, "Invalid message magic field", EXPFILL }},
            { &ei_kafka_pdu_length_mismatch,
                    { "kafka.pdu_length_mismatch", PI_MALFORMED, PI_WARN, "Dissected message does not end at the pdu length offset", EXPFILL }},
            { &ei_kafka_zero_field_length,
                    { "kafka.zero_field_length", PI_MALFORMED, PI_WARN, "Zero length field", EXPFILL }},
    };
    expert_kafka = expert_register_protocol(proto);
    expert_register_field_array(expert_kafka, ei, array_length(ei));
}

static void
proto_register_kafka_preferences(const int proto)
{
    module_t *kafka_module;
    kafka_module = prefs_register_protocol(proto, NULL);
    /* unused; kept for backward compatibility */
    prefs_register_bool_preference(kafka_module, "show_string_bytes_lengths",
                                   "Show length for string and bytes fields in the protocol tree",
                                   "",
                                   &kafka_show_string_bytes_lengths);
}


/*
 * Dissector entry points, contract for dissection plugin.
 */

void
proto_register_kafka(void)
{

    int protocol_handle;

    compute_kafka_api_names();

    protocol_handle = proto_register_protocol("Kafka", "Kafka", "kafka");
    proto_register_kafka_protocol_fields(protocol_handle);
    proto_register_kafka_protocol_subtrees(protocol_handle);
    proto_register_kafka_expert_module(protocol_handle);
    proto_register_kafka_preferences(protocol_handle);

    proto_kafka = protocol_handle;

}

void
proto_reg_handoff_kafka(void)
{

    static dissector_handle_t kafka_handle;

    kafka_handle = register_dissector("kafka", dissect_kafka_tcp, proto_kafka);

    dissector_add_uint_range_with_preference("tcp.port", KAFKA_TCP_DEFAULT_RANGE, kafka_handle);
    ssl_dissector_add(0, kafka_handle);

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
