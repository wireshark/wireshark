/* packet-rtps2.c
 * ~~~~~~~~~~~~~~
 *
 * Routines for Real-Time Publish-Subscribe Protocol (RTPS) dissection
 *
 * Copyright 2005, Fabrizio Bertocci <fabrizio@rti.com>
 * Real-Time Innovations, Inc.
 * 385 Moffett Park Drive
 * Sunnyvale, CA 94089
 *
 * Version 2.1 bug fixes to RTPS_DATA provided by
 * Twin Oaks Computing, Inc.  <contact@twinoakscomputing.com>
 * 755 Maleta Ln, Ste 203
 * Castle Rock, CO 80108
 *
 * $Id$
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
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 *
 *                  -------------------------------------
 *
 * This is the RTPS packet dissector for RTPS version 2.x
 *
 * RTPS protocol was initially developed by Real-Time Innovations, Inc. as wire
 * protocol for Data Distribution System, and then adopted as a standard by
 * the Object Management Group (as version 2.0).
 *
 * Additional information at:
 *   The Real-time Publish-Subscribe Wire Protocol DDS Interoperability Wire Protocol (DDSI):
 *                             http://www.omg.org/spec/DDSI/
 *   Full OMG DDS Standard Specification:
 *                             http://www.omg.org/cgi-bin/doc?ptc/2003-07-07
 *
 *   RTI DDS and RTPS information: http://www.rti.com/resources.html
 *
 */


#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <string.h>
#include <glib.h>
#include <epan/packet.h>
#include <epan/addr_resolv.h>
#include <epan/prefs.h>


#include "packet-rtps2.h"

/* Size of the temp buffers used to format various part of the protocol.
 * Note: Some of those values are bigger than expected. The reason is
 *       because the string buffer can also contains decoded values.
 *       I.e. port size is an integer, but for value 0x0000, it is interpreted
 *       as a string "PORT_INVALID (0x00000000)"
 */
#define MAX_FLAG_SIZE           (40)
#define MAX_GUID_PREFIX_SIZE    (128)
#define MAX_GUID_SIZE           (160)
#define MAX_VENDOR_ID_SIZE      (128)
#define MAX_NTP_TIME_SIZE       (128)
#define MAX_PORT_SIZE           (32)
#define MAX_PARAM_SIZE          (256)
#define MAX_SUMMARY_SIZE        (500)
#define MAX_LOCATOR_SIZE        (200)
#define MAX_IPV6_SIZE           (100)
#define MAX_BITMAP_SIZE         (256)
#define MAX_LABEL_SIZE          (64)
#define MAX_IPV4_ADDRESS_SIZE   (64)

/* Max octets printed on the parameter root for a sequence of octets */
#define MAX_SEQ_OCTETS_PRINTED  (20)


/***************************************************************************/
/* Protocol Fields Identifiers */
static int proto_rtps                           = -1;
static int hf_rtps_protocol_version             = -1;
static int hf_rtps_protocol_version_major       = -1;
static int hf_rtps_protocol_version_minor       = -1;
static int hf_rtps_vendor_id                    = -1;

static int hf_rtps_domain_id                    = -1;
static int hf_rtps_participant_idx              = -1;
static int hf_rtps_nature_type                  = -1;

static int hf_rtps_guid_prefix                  = -1;
static int hf_rtps_host_id                      = -1;
static int hf_rtps_app_id                       = -1;
static int hf_rtps_counter                      = -1;

static int hf_rtps_sm_id                        = -1;
static int hf_rtps_sm_flags                     = -1;
static int hf_rtps_sm_octets_to_next_header     = -1;
static int hf_rtps_sm_guid_prefix               = -1;
static int hf_rtps_sm_host_id                   = -1;
static int hf_rtps_sm_app_id                    = -1;
static int hf_rtps_sm_instance_id               = -1;
static int hf_rtps_sm_app_kind                  = -1;
static int hf_rtps_sm_counter                   = -1;
static int hf_rtps_sm_entity_id                 = -1;
static int hf_rtps_sm_entity_id_key             = -1;
static int hf_rtps_sm_entity_id_kind            = -1;
static int hf_rtps_sm_rdentity_id               = -1;
static int hf_rtps_sm_rdentity_id_key           = -1;
static int hf_rtps_sm_rdentity_id_kind          = -1;
static int hf_rtps_sm_wrentity_id               = -1;
static int hf_rtps_sm_wrentity_id_key           = -1;
static int hf_rtps_sm_wrentity_id_kind          = -1;
static int hf_rtps_sm_seq_number                = -1;

static int hf_rtps_parameter_id                 = -1;
static int hf_rtps_parameter_length             = -1;
static int hf_rtps_param_ntpt                   = -1;
static int hf_rtps_param_ntpt_sec               = -1;
static int hf_rtps_param_ntpt_fraction          = -1;
static int hf_rtps_param_topic_name             = -1;
static int hf_rtps_param_entity_name            = -1;
static int hf_rtps_param_strength               = -1;
static int hf_rtps_param_type_name              = -1;
static int hf_rtps_param_user_data              = -1;
static int hf_rtps_param_group_data             = -1;
static int hf_rtps_param_topic_data             = -1;
static int hf_rtps_param_content_filter_name    = -1;
static int hf_rtps_param_related_topic_name     = -1;
static int hf_rtps_param_filter_name            = -1;
static int hf_rtps_issue_data                   = -1;
static int hf_rtps_param_status_info            = -1;


/* Subtree identifiers */
static gint ett_rtps                            = -1;
static gint ett_rtps_default_mapping            = -1;
static gint ett_rtps_proto_version              = -1;
static gint ett_rtps_submessage                 = -1;
static gint ett_rtps_parameter_sequence         = -1;
static gint ett_rtps_parameter                  = -1;
static gint ett_rtps_flags                      = -1;
static gint ett_rtps_entity                     = -1;
static gint ett_rtps_rdentity                   = -1;
static gint ett_rtps_wrentity                   = -1;
static gint ett_rtps_guid_prefix                = -1;
static gint ett_rtps_part_message_data          = -1;
static gint ett_rtps_part_message_guid          = -1;
static gint ett_rtps_locator_udp_v4             = -1;
static gint ett_rtps_locator                    = -1;
static gint ett_rtps_locator_list               = -1;
static gint ett_rtps_ntp_time                   = -1;
static gint ett_rtps_bitmap                     = -1;
static gint ett_rtps_seq_string                 = -1;
static gint ett_rtps_seq_ulong                  = -1;
static gint ett_rtps_serialized_data            = -1;
static gint ett_rtps_sample_info_list           = -1;
static gint ett_rtps_sample_info                = -1;
static gint ett_rtps_sample_batch_list          = -1;
static gint ett_rtps_locator_filter_channel     = -1;
static gint ett_rtps_locator_filter_locator     = -1;

/***************************************************************************/
/* Value-to-String Tables */
static const value_string entity_id_vals[] = {
  { ENTITYID_UNKNOWN,                                   "ENTITYID_UNKNOWN" },
  { ENTITYID_PARTICIPANT,                               "ENTITYID_PARTICIPANT" },
  { ENTITYID_SEDP_BUILTIN_TOPIC_WRITER,                 "ENTITYID_SEDP_BUILTIN_TOPIC_WRITER" },
  { ENTITYID_SEDP_BUILTIN_TOPIC_READER,                 "ENTITYID_SEDP_BUILTIN_TOPIC_READER" },
  { ENTITYID_SEDP_BUILTIN_PUBLICATIONS_WRITER,          "ENTITYID_SEDP_BUILTIN_PUBLICATIONS_WRITER" },
  { ENTITYID_SEDP_BUILTIN_PUBLICATIONS_READER,          "ENTITYID_SEDP_BUILTIN_PUBLICATIONS_READER" },
  { ENTITYID_SEDP_BUILTIN_SUBSCRIPTIONS_WRITER,         "ENTITYID_SEDP_BUILTIN_SUBSCRIPTIONS_WRITER" },
  { ENTITYID_SEDP_BUILTIN_SUBSCRIPTIONS_READER,         "ENTITYID_SEDP_BUILTIN_SUBSCRIPTIONS_READER" },
  { ENTITYID_SPDP_BUILTIN_PARTICIPANT_WRITER,           "ENTITYID_SPDP_BUILTIN_PARTICIPANT_WRITER" },
  { ENTITYID_SPDP_BUILTIN_PARTICIPANT_READER,           "ENTITYID_SPDP_BUILTIN_PARTICIPANT_READER" },
  { ENTITYID_P2P_BUILTIN_PARTICIPANT_MESSAGE_WRITER,    "ENTITYID_P2P_BUILTIN_PARTICIPANT_MESSAGE_WRITER" },
  { ENTITYID_P2P_BUILTIN_PARTICIPANT_MESSAGE_READER,    "ENTITYID_P2P_BUILTIN_PARTICIPANT_MESSAGE_READER" },

  /* Deprecated Items */
  { ENTITYID_APPLICATIONS_WRITER,                        "writerApplications [DEPRECATED]" },
  { ENTITYID_APPLICATIONS_READER,                        "readerApplications [DEPRECATED]" },
  { ENTITYID_CLIENTS_WRITER,                             "writerClients [DEPRECATED]" },
  { ENTITYID_CLIENTS_READER,                             "readerClients [DEPRECATED]" },
  { ENTITYID_SERVICES_WRITER,                            "writerServices [DEPRECATED]" },
  { ENTITYID_SERVICES_READER,                            "readerServices [DEPRECATED]" },
  { ENTITYID_MANAGERS_WRITER,                            "writerManagers [DEPRECATED]" },
  { ENTITYID_MANAGERS_READER,                            "readerManagers [DEPRECATED]" },
  { ENTITYID_APPLICATION_SELF,                           "applicationSelf [DEPRECATED]" },
  { ENTITYID_APPLICATION_SELF_WRITER,                    "writerApplicationSelf [DEPRECATED]" },
  { ENTITYID_APPLICATION_SELF_READER,                    "readerApplicationSelf [DEPRECATED]" },
  { 0, NULL }
};

static const value_string entity_kind_vals [] = {
  { ENTITYKIND_APPDEF_UNKNOWN,                  "Application-defined unknown kind" },
  { ENTITYKIND_APPDEF_PARTICIPANT,              "Application-defined participant" },
  { ENTITYKIND_APPDEF_WRITER_WITH_KEY,          "Application-defined writer (with key)" },
  { ENTITYKIND_APPDEF_WRITER_NO_KEY,            "Application-defined writer (no key)" },
  { ENTITYKIND_APPDEF_READER_WITH_KEY,          "Application-defined reader (with key)" },
  { ENTITYKIND_APPDEF_READER_NO_KEY,            "Application-defined reader (no key)" },
  { ENTITYKIND_BUILTIN_PARTICIPANT,             "Built-in participant" },
  { ENTITYKIND_BUILTIN_WRITER_WITH_KEY,         "Built-in writer (with key)" },
  { ENTITYKIND_BUILTIN_WRITER_NO_KEY,           "Built-in writer (no key)" },
  { ENTITYKIND_BUILTIN_READER_WITH_KEY,         "Built-in reader (with key)" },
  { ENTITYKIND_BUILTIN_READER_NO_KEY,           "Built-in reader (no key)" },
  { 0, NULL }
};


static const value_string nature_type_vals[] = {
  { PORT_METATRAFFIC_UNICAST,           "UNICAST_METATRAFFIC"},
  { PORT_METATRAFFIC_MULTICAST,         "MULTICAST_METATRAFFIC"},
  { PORT_USERTRAFFIC_UNICAST,           "UNICAST_USERTRAFFIC"},
  { PORT_USERTRAFFIC_MULTICAST,         "MULTICAST_USERTRAFFIC"},
  { 0, NULL }
};


static const value_string app_kind_vals[] = {
  { APPKIND_UNKNOWN,                    "APPKIND_UNKNOWN" },
  { APPKIND_MANAGED_APPLICATION,        "ManagedApplication" },
  { APPKIND_MANAGER,                    "Manager" },
  { 0, NULL }
};


static const value_string submessage_id_vals[] = {
  { SUBMESSAGE_PAD,                     "PAD" },
  { SUBMESSAGE_RTPS_DATA,               "DATA" },
  { SUBMESSAGE_RTPS_DATA_FRAG,          "DATA_FRAG" },
  { SUBMESSAGE_RTPS_DATA_BATCH,         "DATA_BATCH" },
  { SUBMESSAGE_ACKNACK,                 "ACKNACK" },
  { SUBMESSAGE_HEARTBEAT,               "HEARTBEAT" },
  { SUBMESSAGE_GAP,                     "GAP" },
  { SUBMESSAGE_INFO_TS,                 "INFO_TS" },
  { SUBMESSAGE_INFO_SRC,                "INFO_SRC" },
  { SUBMESSAGE_INFO_REPLY_IP4,          "INFO_REPLY_IP4" },
  { SUBMESSAGE_INFO_DST,                "INFO_DST" },
  { SUBMESSAGE_INFO_REPLY,              "INFO_REPLY" },
  { SUBMESSAGE_NACK_FRAG,               "NACK_FRAG" },
  { SUBMESSAGE_HEARTBEAT_FRAG,          "HEARTBEAT_FRAG" },
  { SUBMESSAGE_ACKNACK_BATCH,           "ACKNACK_BATCH" },
  { SUBMESSAGE_HEARTBEAT_BATCH,         "HEARTBEAT_BATCH" },
  { SUBMESSAGE_ACKNACK_SESSION,         "ACKNACK_SESSION" },
  { SUBMESSAGE_HEARTBEAT_SESSION,       "HEARTBEAT_SESSION" },
  { SUBMESSAGE_RTPS_DATA_SESSION,       "DATA_SESSION" },
  /* Deprecated submessages */
  { SUBMESSAGE_DATA,                    "DATA_deprecated" },
  { SUBMESSAGE_NOKEY_DATA,              "NOKEY_DATA_deprecated" },
  { SUBMESSAGE_DATA_FRAG,               "DATA_FRAG_deprecated" },
  { SUBMESSAGE_NOKEY_DATA_FRAG,         "NOKEY_DATA_FRAG_deprecated" },
  { 0, NULL }
};

static const value_string typecode_kind_vals[] = {
  { RTI_CDR_TK_NULL,                    "(unknown)" },
  { RTI_CDR_TK_SHORT,                   "short" },
  { RTI_CDR_TK_LONG,                    "long" },
  { RTI_CDR_TK_USHORT,                  "unsigned short" },
  { RTI_CDR_TK_ULONG,                   "unsigned long" },
  { RTI_CDR_TK_FLOAT,                   "float" },
  { RTI_CDR_TK_DOUBLE,                  "double" },
  { RTI_CDR_TK_BOOLEAN,                 "boolean" },
  { RTI_CDR_TK_CHAR,                    "char" },
  { RTI_CDR_TK_OCTET,                   "octet" },
  { RTI_CDR_TK_STRUCT,                  "struct" },
  { RTI_CDR_TK_UNION,                   "union" },
  { RTI_CDR_TK_ENUM,                    "enum" },
  { RTI_CDR_TK_STRING,                  "string" },
  { RTI_CDR_TK_SEQUENCE,                "sequence" },
  { RTI_CDR_TK_ARRAY,                   "array" },
  { RTI_CDR_TK_ALIAS,                   "alias" },
  { RTI_CDR_TK_LONGLONG,                "long long" },
  { RTI_CDR_TK_ULONGLONG,               "unsigned long long" },
  { RTI_CDR_TK_LONGDOUBLE,              "long double" },
  { RTI_CDR_TK_WCHAR,                   "wchar" },
  { RTI_CDR_TK_WSTRING,                 "wstring" },
  { 0,                                  NULL }
};

static const value_string parameter_id_vals[] = {
  { PID_PAD,                            "PID_PAD" },
  { PID_SENTINEL,                       "PID_SENTINEL" },
  { PID_PARTICIPANT_LEASE_DURATION,     "PID_PARTICIPANT_LEASE_DURATION" },
  { PID_TIME_BASED_FILTER,              "PID_TIME_BASED_FILTER" },
  { PID_TOPIC_NAME,                     "PID_TOPIC_NAME" },
  { PID_OWNERSHIP_STRENGTH,             "PID_OWNERSHIP_STRENGTH" },
  { PID_TYPE_NAME,                      "PID_TYPE_NAME" },
  { PID_METATRAFFIC_MULTICAST_IPADDRESS,"PID_METATRAFFIC_MULTICAST_IPADDRESS"},
  { PID_DEFAULT_UNICAST_IPADDRESS,      "PID_DEFAULT_UNICAST_IPADDRESS" },
  { PID_METATRAFFIC_UNICAST_PORT,       "PID_METATRAFFIC_UNICAST_PORT" },
  { PID_DEFAULT_UNICAST_PORT,           "PID_DEFAULT_UNICAST_PORT" },
  { PID_MULTICAST_IPADDRESS,            "PID_MULTICAST_IPADDRESS" },
  { PID_PROTOCOL_VERSION,               "PID_PROTOCOL_VERSION" },
  { PID_VENDOR_ID,                      "PID_VENDOR_ID" },
  { PID_RELIABILITY,                    "PID_RELIABILITY" },
  { PID_LIVELINESS,                     "PID_LIVELINESS" },
  { PID_DURABILITY,                     "PID_DURABILITY" },
  { PID_DURABILITY_SERVICE,             "PID_DURABILITY_SERVICE" },
  { PID_OWNERSHIP,                      "PID_OWNERSHIP" },
  { PID_PRESENTATION,                   "PID_PRESENTATION" },
  { PID_DEADLINE,                       "PID_DEADLINE" },
  { PID_DESTINATION_ORDER,              "PID_DESTINATION_ORDER" },
  { PID_LATENCY_BUDGET,                 "PID_LATENCY_BUDGET" },
  { PID_PARTITION,                      "PID_PARTITION" },
  { PID_LIFESPAN,                       "PID_LIFESPAN" },
  { PID_USER_DATA,                      "PID_USER_DATA" },
  { PID_GROUP_DATA,                     "PID_GROUP_DATA" },
  { PID_TOPIC_DATA,                     "PID_TOPIC_DATA" },
  { PID_UNICAST_LOCATOR,                "PID_UNICAST_LOCATOR" },
  { PID_MULTICAST_LOCATOR,              "PID_MULTICAST_LOCATOR" },
  { PID_DEFAULT_UNICAST_LOCATOR,        "PID_DEFAULT_UNICAST_LOCATOR" },
  { PID_METATRAFFIC_UNICAST_LOCATOR,    "PID_METATRAFFIC_UNICAST_LOCATOR " },
  { PID_METATRAFFIC_MULTICAST_LOCATOR,  "PID_METATRAFFIC_MULTICAST_LOCATOR" },
  { PID_PARTICIPANT_MANUAL_LIVELINESS_COUNT, "PID_PARTICIPANT_MANUAL_LIVELINESS_COUNT" },
  { PID_CONTENT_FILTER_PROPERTY,        "PID_CONTENT_FILTER_PROPERTY" },
  { PID_PROPERTY_LIST,                  "PID_PROPERTY_LIST" },
  { PID_HISTORY,                        "PID_HISTORY" },
  { PID_RESOURCE_LIMIT,                 "PID_RESOURCE_LIMIT" },
  { PID_EXPECTS_INLINE_QOS,             "PID_EXPECTS_INLINE_QOS" },
  { PID_PARTICIPANT_BUILTIN_ENDPOINTS,  "PID_PARTICIPANT_BUILTIN_ENDPOINTS" },
  { PID_METATRAFFIC_UNICAST_IPADDRESS,  "PID_METATRAFFIC_UNICAST_IPADDRESS" },
  { PID_METATRAFFIC_MULTICAST_PORT,     "PID_METATRAFFIC_MULTICAST_PORT" },
  { PID_DEFAULT_MULTICAST_LOCATOR,      "PID_DEFAULT_MULTICAST_LOCATOR" },
  { PID_TRANSPORT_PRIORITY,             "PID_TRANSPORT_PRIORITY" },
  { PID_PARTICIPANT_GUID,               "PID_PARTICIPANT_GUID" },
  { PID_PARTICIPANT_ENTITY_ID,          "PID_PARTICIPANT_ENTITY_ID" },
  { PID_GROUP_GUID,                     "PID_GROUP_GUID" },
  { PID_GROUP_ENTITY_ID,                "PID_GROUP_ENTITY_ID" },
  { PID_CONTENT_FILTER_INFO,            "PID_CONTENT_FILTER_INFO" },
  { PID_COHERENT_SET,                   "PID_COHERENT_SET" },
  { PID_DIRECTED_WRITE,                 "PID_DIRECTED_WRITE" },
  { PID_BUILTIN_ENDPOINT_SET,           "PID_BUILTIN_ENDPOINT_SET" },
  { PID_PROPERTY_LIST_OLD,              "PID_PROPERTY_LIST" },
  { PID_ENDPOINT_GUID,                  "PID_ENDPOINT_GUID" },
  { PID_TYPE_MAX_SIZE_SERIALIZED,       "PID_TYPE_MAX_SIZE_SERIALIZED" },
  { PID_ORIGINAL_WRITER_INFO,           "PID_ORIGINAL_WRITER_INFO" },
  { PID_ENTITY_NAME,                    "PID_ENTITY_NAME" },
  { PID_KEY_HASH,                       "PID_KEY_HASH" },
  { PID_STATUS_INFO,                    "PID_STATUS_INFO" },

  /* Vendor specific: RTI */
  { PID_PRODUCT_VERSION,                "PID_PRODUCT_VERSION" },
  { PID_PLUGIN_PROMISCUITY_KIND,        "PID_PLUGIN_PROMISCUITY_KIND" },
  { PID_ENTITY_VIRTUAL_GUID,            "PID_ENTITY_VIRTUAL_GUID" },
  { PID_SERVICE_KIND,                   "PID_SERVICE_KIND" },
  { PID_TYPECODE,                       "PID_TYPECODE" },
  { PID_DISABLE_POSITIVE_ACKS,          "PID_DISABLE_POSITIVE_ACKS" },
  { PID_LOCATOR_FILTER_LIST,            "PID_LOCATOR_FILTER_LIST" },

  /* The following PID are deprecated */
  { PID_DEADLINE_OFFERED,               "PID_DEADLINE_OFFERED [deprecated]" },
  { PID_PERSISTENCE,                    "PID_PERSISTENCE [deprecated]" },
  { PID_TYPE_CHECKSUM,                  "PID_TYPE_CHECKSUM [deprecated]" },
  { PID_TYPE2_NAME,                     "PID_TYPE2_NAME [deprecated]" },
  { PID_TYPE2_CHECKSUM,                 "PID_TYPE2_CHECKSUM [deprecated]" },
  { PID_IS_RELIABLE,                    "PID_IS_RELIABLE [deprecated]" },
  { PID_EXPECTS_ACK,                    "PID_EXPECTS_ACK [deprecated]" },
  { PID_MANAGER_KEY,                    "PID_MANAGER_KEY [deprecated]" },
  { PID_SEND_QUEUE_SIZE,                "PID_SEND_QUEUE_SIZE [deprecated]" },
  { PID_RELIABILITY_ENABLED,            "PID_RELIABILITY_ENABLED [deprecated]" },
  { PID_VARGAPPS_SEQUENCE_NUMBER_LAST,  "PID_VARGAPPS_SEQUENCE_NUMBER_LAST [deprecated]" },
  { PID_RECV_QUEUE_SIZE,                "PID_RECV_QUEUE_SIZE [deprecated]" },
  { PID_RELIABILITY_OFFERED,            "PID_RELIABILITY_OFFERED [deprecated]" },
  { PID_LIVELINESS_OFFERED,             "PID_LIVELINESS_OFFERED [deprecated]" },
  { PID_PRESENTATION_OFFERED,           "PID_PRESENTATION_OFFERED [deprecated]" },
  { PID_OWNERSHIP_OFFERED,              "PID_OWNERSHIP_OFFERED [deprecated]" },
  { PID_DESTINATION_ORDER_OFFERED,      "PID_DESTINATION_ORDER_OFFERED [deprecated]" },
  { PID_LATENCY_BUDGET_OFFERED,         "PID_LATENCY_BUDGET_OFFERED [deprecated]" },
  { PID_PARTITION_OFFERED,              "PID_PARTITION_OFFERED [deprecated]" },
  { 0, NULL }
};

static const value_string liveliness_qos_vals[] = {
  { LIVELINESS_AUTOMATIC,               "AUTOMATIC_LIVELINESS_QOS" },
  { LIVELINESS_BY_PARTICIPANT,          "MANUAL_BY_PARTICIPANT_LIVELINESS_QOS" },
  { LIVELINESS_BY_TOPIC,                "MANUAL_BY_TOPIC_LIVELINESS_QOS" },
  { 0, NULL }
};

static const value_string durability_qos_vals[] = {
  { DURABILITY_VOLATILE,                "VOLATILE_DURABILITY_QOS" },
  { DURABILITY_TRANSIENT_LOCAL,         "TRANSIENT_LOCAL_DURABILITY_QOS" },
  { DURABILITY_TRANSIENT,               "TRANSIENT_DURABILITY_QOS" },
  { DURABILITY_PERSISTENT,              "PERSISTENT_DURABILITY_QOS" },
  { 0, NULL }
};

static const value_string ownership_qos_vals[] = {
  { OWNERSHIP_SHARED,                   "SHARED_OWNERSHIP_QOS" },
  { OWNERSHIP_EXCLUSIVE,                "EXCLUSIVE_OWNERSHIP_QOS" },
  { 0, NULL }
};

static const value_string presentation_qos_vals[] = {
  { PRESENTATION_INSTANCE,              "INSTANCE_PRESENTATION_QOS" },
  { PRESENTATION_TOPIC,                 "TOPIC_PRESENTATION_QOS" },
  { PRESENTATION_GROUP,                 "GROUP_PRESENTATION_QOS" },
  { 0, NULL }
};

static const value_string history_qos_vals[] = {
  { HISTORY_KIND_KEEP_LAST,             "KEEP_LAST_HISTORY_QOS" },
  { HISTORY_KIND_KEEP_ALL,              "KEEP_ALL_HISTORY_QOS" },
  { 0, NULL }
};

static const value_string reliability_qos_vals[] = {
  { RELIABILITY_BEST_EFFORT,            "BEST_EFFORT_RELIABILITY_QOS" },
  { RELIABILITY_RELIABLE,               "RELIABLE_RELIABILITY_QOS" },
  { 0, NULL }
};

static const value_string destination_order_qos_vals[] = {
  { BY_RECEPTION_TIMESTAMP,             "BY_RECEPTION_TIMESTAMP_DESTINATIONORDER_QOS" },
  { BY_SOURCE_TIMESTAMP,                "BY_SOURCE_TIMESTAMP_DESTINATIONORDER_QOS" },
  { 0, NULL }
};


static const value_string encapsulation_id_vals[] = {
  { ENCAPSULATION_CDR_BE,               "CDR_BE" },
  { ENCAPSULATION_CDR_LE,               "CDR_LE" },
  { ENCAPSULATION_PL_CDR_BE,            "PL_CDR_BE" },
  { ENCAPSULATION_PL_CDR_LE,            "PL_CDR_LE" },
  { 0, NULL }
};

static const value_string plugin_promiscuity_kind_vals[] = {
  { 0x0001,                             "MATCHING_REMOTE_ENTITIES_PROMISCUITY" },
  { 0xffff,                             "ALL_REMOTE_ENTITIES_PROMISCUITY" },
  { 0, NULL }
};

static const value_string service_kind_vals[] = {
  { 0x00000000,                             "NO_SERVICE_QOS" },
  { 0x00000001,                             "PERSISTENCE_SERVICE_QOS" },
  { 0, NULL }
};

static const value_string participant_message_data_kind [] = {
  { PARTICIPANT_MESSAGE_DATA_KIND_UNKNOWN,      "PARTICIPANT_MESSAGE_DATA_KIND_UNKNOWN" },
  { PARTICIPANT_MESSAGE_DATA_KIND_AUTOMATIC_LIVELINESS_UPDATE,  "PARTICIPANT_MESSAGE_DATA_KIND_AUTOMATIC_LIVELINESS_UPDATE" },
  { PARTICIPANT_MESSAGE_DATA_KIND_MANUAL_LIVELINESS_UPDATE,     "PARTICIPANT_MESSAGE_DATA_KIND_MANUAL_LIVELINESS_UPDATE" },
  { 0, NULL }
};



/* Flag Decoding defintions ***********************************************/
struct Flag_definition {
  const char letter;
  const char *description;
};

#define RESERVEDFLAG_CHAR               ('_')
#define RESERVEDFLAG_STRING             ("reserved bit")

static const struct Flag_definition PAD_FLAGS[] = {
  { RESERVEDFLAG_CHAR, RESERVEDFLAG_STRING },   /* Bit 7 */
  { RESERVEDFLAG_CHAR, RESERVEDFLAG_STRING },   /* Bit 6 */
  { RESERVEDFLAG_CHAR, RESERVEDFLAG_STRING },   /* Bit 5 */
  { RESERVEDFLAG_CHAR, RESERVEDFLAG_STRING },   /* Bit 4 */
  { RESERVEDFLAG_CHAR, RESERVEDFLAG_STRING },   /* Bit 3 */
  { RESERVEDFLAG_CHAR, RESERVEDFLAG_STRING },   /* Bit 2 */
  { RESERVEDFLAG_CHAR, RESERVEDFLAG_STRING },   /* Bit 1 */
  { 'E', "Endianness bit" }                     /* Bit 0 */
};

static const struct Flag_definition DATA_FLAGS[] = {
  { RESERVEDFLAG_CHAR, RESERVEDFLAG_STRING },   /* Bit 7 */
  { RESERVEDFLAG_CHAR, RESERVEDFLAG_STRING },   /* Bit 6 */
  { RESERVEDFLAG_CHAR, RESERVEDFLAG_STRING },   /* Bit 5 */
  { 'I', "Status info flag" },                  /* Bit 4 */
  { 'H', "Hash key flag" },                     /* Bit 3 */
  { 'D', "Data present" },                      /* Bit 2 */
  { 'Q', "Inline QoS" },                        /* Bit 1 */
  { 'E', "Endianness bit" }                     /* Bit 0 */
};

static const struct Flag_definition NOKEY_DATA_FLAGS[] = {
  { RESERVEDFLAG_CHAR, RESERVEDFLAG_STRING },   /* Bit 7 */
  { RESERVEDFLAG_CHAR, RESERVEDFLAG_STRING },   /* Bit 6 */
  { RESERVEDFLAG_CHAR, RESERVEDFLAG_STRING },   /* Bit 5 */
  { RESERVEDFLAG_CHAR, RESERVEDFLAG_STRING },   /* Bit 4 */
  { RESERVEDFLAG_CHAR, RESERVEDFLAG_STRING },   /* Bit 3 */
  { 'H', "Key Hash" },                          /* Bit 2 */
  { 'Q', "Inline QoS" },                        /* Bit 1 */
  { 'E', "Endianness bit" }                     /* Bit 0 */
};

static const struct Flag_definition ACKNACK_FLAGS[] = {
  { RESERVEDFLAG_CHAR, RESERVEDFLAG_STRING },   /* Bit 7 */
  { RESERVEDFLAG_CHAR, RESERVEDFLAG_STRING },   /* Bit 6 */
  { RESERVEDFLAG_CHAR, RESERVEDFLAG_STRING },   /* Bit 5 */
  { RESERVEDFLAG_CHAR, RESERVEDFLAG_STRING },   /* Bit 4 */
  { RESERVEDFLAG_CHAR, RESERVEDFLAG_STRING },   /* Bit 3 */
  { RESERVEDFLAG_CHAR, RESERVEDFLAG_STRING },   /* Bit 2 */
  { 'F', "Final flag" },                        /* Bit 1 */
  { 'E', "Endianness bit" }                     /* Bit 0 */
};

static const struct Flag_definition GAP_FLAGS[] = {
  { RESERVEDFLAG_CHAR, RESERVEDFLAG_STRING },   /* Bit 7 */
  { RESERVEDFLAG_CHAR, RESERVEDFLAG_STRING },   /* Bit 6 */
  { RESERVEDFLAG_CHAR, RESERVEDFLAG_STRING },   /* Bit 5 */
  { RESERVEDFLAG_CHAR, RESERVEDFLAG_STRING },   /* Bit 4 */
  { RESERVEDFLAG_CHAR, RESERVEDFLAG_STRING },   /* Bit 3 */
  { RESERVEDFLAG_CHAR, RESERVEDFLAG_STRING },   /* Bit 2 */
  { RESERVEDFLAG_CHAR, RESERVEDFLAG_STRING },   /* Bit 1 */
  { 'E', "Endianness bit" }                     /* Bit 0 */
};

static const struct Flag_definition HEARTBEAT_FLAGS[] = {
  { RESERVEDFLAG_CHAR, RESERVEDFLAG_STRING },   /* Bit 7 */
  { RESERVEDFLAG_CHAR, RESERVEDFLAG_STRING },   /* Bit 6 */
  { RESERVEDFLAG_CHAR, RESERVEDFLAG_STRING },   /* Bit 5 */
  { RESERVEDFLAG_CHAR, RESERVEDFLAG_STRING },   /* Bit 4 */
  { RESERVEDFLAG_CHAR, RESERVEDFLAG_STRING },   /* Bit 3 */
  { 'L', "Liveliness flag" },                   /* Bit 2 */
  { 'F', "Final flag" },                        /* Bit 1 */
  { 'E', "Endianness bit" }                     /* Bit 0 */
};

static const struct Flag_definition HEARTBEAT_BATCH_FLAGS[] = {
  { RESERVEDFLAG_CHAR, RESERVEDFLAG_STRING },   /* Bit 7 */
  { RESERVEDFLAG_CHAR, RESERVEDFLAG_STRING },   /* Bit 6 */
  { RESERVEDFLAG_CHAR, RESERVEDFLAG_STRING },   /* Bit 5 */
  { RESERVEDFLAG_CHAR, RESERVEDFLAG_STRING },   /* Bit 4 */
  { RESERVEDFLAG_CHAR, RESERVEDFLAG_STRING },   /* Bit 3 */
  { 'L', "Liveliness flag" },                   /* Bit 2 */
  { 'F', "Final flag" },                        /* Bit 1 */
  { 'E', "Endianness bit" }                     /* Bit 0 */
};

static const struct Flag_definition INFO_TS_FLAGS[] = {
  { RESERVEDFLAG_CHAR, RESERVEDFLAG_STRING },   /* Bit 7 */
  { RESERVEDFLAG_CHAR, RESERVEDFLAG_STRING },   /* Bit 6 */
  { RESERVEDFLAG_CHAR, RESERVEDFLAG_STRING },   /* Bit 5 */
  { RESERVEDFLAG_CHAR, RESERVEDFLAG_STRING },   /* Bit 4 */
  { RESERVEDFLAG_CHAR, RESERVEDFLAG_STRING },   /* Bit 3 */
  { RESERVEDFLAG_CHAR, RESERVEDFLAG_STRING },   /* Bit 2 */
  { 'I', "Invalidate flag" },                   /* Bit 1 */
  { 'E', "Endianness bit" }                     /* Bit 0 */
};

static const struct Flag_definition INFO_SRC_FLAGS[] = {
  { RESERVEDFLAG_CHAR, RESERVEDFLAG_STRING },   /* Bit 7 */
  { RESERVEDFLAG_CHAR, RESERVEDFLAG_STRING },   /* Bit 6 */
  { RESERVEDFLAG_CHAR, RESERVEDFLAG_STRING },   /* Bit 5 */
  { RESERVEDFLAG_CHAR, RESERVEDFLAG_STRING },   /* Bit 4 */
  { RESERVEDFLAG_CHAR, RESERVEDFLAG_STRING },   /* Bit 3 */
  { RESERVEDFLAG_CHAR, RESERVEDFLAG_STRING },   /* Bit 2 */
  { RESERVEDFLAG_CHAR, RESERVEDFLAG_STRING },   /* Bit 1 */
  { 'E', "Endianness bit" }                     /* Bit 0 */
};

static const struct Flag_definition INFO_REPLY_IP4_FLAGS[] = {
  { RESERVEDFLAG_CHAR, RESERVEDFLAG_STRING },   /* Bit 7 */
  { RESERVEDFLAG_CHAR, RESERVEDFLAG_STRING },   /* Bit 6 */
  { RESERVEDFLAG_CHAR, RESERVEDFLAG_STRING },   /* Bit 5 */
  { RESERVEDFLAG_CHAR, RESERVEDFLAG_STRING },   /* Bit 4 */
  { RESERVEDFLAG_CHAR, RESERVEDFLAG_STRING },   /* Bit 3 */
  { RESERVEDFLAG_CHAR, RESERVEDFLAG_STRING },   /* Bit 2 */
  { 'M', "Multicast flag" },                    /* Bit 1 */
  { 'E', "Endianness bit" }                     /* Bit 0 */
};

static const struct Flag_definition INFO_DST_FLAGS[] = {
  { RESERVEDFLAG_CHAR, RESERVEDFLAG_STRING },   /* Bit 7 */
  { RESERVEDFLAG_CHAR, RESERVEDFLAG_STRING },   /* Bit 6 */
  { RESERVEDFLAG_CHAR, RESERVEDFLAG_STRING },   /* Bit 5 */
  { RESERVEDFLAG_CHAR, RESERVEDFLAG_STRING },   /* Bit 4 */
  { RESERVEDFLAG_CHAR, RESERVEDFLAG_STRING },   /* Bit 3 */
  { RESERVEDFLAG_CHAR, RESERVEDFLAG_STRING },   /* Bit 2 */
  { RESERVEDFLAG_CHAR, RESERVEDFLAG_STRING },   /* Bit 1 */
  { 'E', "Endianness bit" }                     /* Bit 0 */
};

static const struct Flag_definition INFO_REPLY_FLAGS[] = {
  { RESERVEDFLAG_CHAR, RESERVEDFLAG_STRING },   /* Bit 7 */
  { RESERVEDFLAG_CHAR, RESERVEDFLAG_STRING },   /* Bit 6 */
  { RESERVEDFLAG_CHAR, RESERVEDFLAG_STRING },   /* Bit 5 */
  { RESERVEDFLAG_CHAR, RESERVEDFLAG_STRING },   /* Bit 4 */
  { RESERVEDFLAG_CHAR, RESERVEDFLAG_STRING },   /* Bit 3 */
  { RESERVEDFLAG_CHAR, RESERVEDFLAG_STRING },   /* Bit 2 */
  { 'M', "Multicast flag" },                    /* Bit 1 */
  { 'E', "Endianness bit" }                     /* Bit 0 */
};

static const struct Flag_definition NOKEY_DATA_FRAG_FLAGS[] = {
  { RESERVEDFLAG_CHAR, RESERVEDFLAG_STRING },   /* Bit 7 */
  { RESERVEDFLAG_CHAR, RESERVEDFLAG_STRING },   /* Bit 6 */
  { RESERVEDFLAG_CHAR, RESERVEDFLAG_STRING },   /* Bit 5 */
  { RESERVEDFLAG_CHAR, RESERVEDFLAG_STRING },   /* Bit 4 */
  { RESERVEDFLAG_CHAR, RESERVEDFLAG_STRING },   /* Bit 3 */
  { RESERVEDFLAG_CHAR, RESERVEDFLAG_STRING },   /* Bit 2 */
  { 'Q', "Inline QoS" },                        /* Bit 1 */
  { 'E', "Endianness bit" }                     /* Bit 0 */
};

static const struct Flag_definition HEARTBEAT_FRAG_FLAGS[] = {
  { RESERVEDFLAG_CHAR, RESERVEDFLAG_STRING },   /* Bit 7 */
  { RESERVEDFLAG_CHAR, RESERVEDFLAG_STRING },   /* Bit 6 */
  { RESERVEDFLAG_CHAR, RESERVEDFLAG_STRING },   /* Bit 5 */
  { RESERVEDFLAG_CHAR, RESERVEDFLAG_STRING },   /* Bit 4 */
  { RESERVEDFLAG_CHAR, RESERVEDFLAG_STRING },   /* Bit 3 */
  { RESERVEDFLAG_CHAR, RESERVEDFLAG_STRING },   /* Bit 2 */
  { RESERVEDFLAG_CHAR, RESERVEDFLAG_STRING },   /* Bit 1 */
  { 'E', "Endianness bit" }                     /* Bit 0 */
};

static const struct Flag_definition NACK_FLAGS[] = {
  { RESERVEDFLAG_CHAR, RESERVEDFLAG_STRING },   /* Bit 7 */
  { RESERVEDFLAG_CHAR, RESERVEDFLAG_STRING },   /* Bit 6 */
  { RESERVEDFLAG_CHAR, RESERVEDFLAG_STRING },   /* Bit 5 */
  { RESERVEDFLAG_CHAR, RESERVEDFLAG_STRING },   /* Bit 4 */
  { RESERVEDFLAG_CHAR, RESERVEDFLAG_STRING },   /* Bit 3 */
  { RESERVEDFLAG_CHAR, RESERVEDFLAG_STRING },   /* Bit 2 */
  { 'F', "Final flag" },                        /* Bit 1 */
  { 'E', "Endianness bit" }                     /* Bit 0 */
};

static const struct Flag_definition DATA_FRAG_FLAGS[] = {
  { RESERVEDFLAG_CHAR, RESERVEDFLAG_STRING },   /* Bit 7 */
  { RESERVEDFLAG_CHAR, RESERVEDFLAG_STRING },   /* Bit 6 */
  { RESERVEDFLAG_CHAR, RESERVEDFLAG_STRING },   /* Bit 5 */
  { RESERVEDFLAG_CHAR, RESERVEDFLAG_STRING },   /* Bit 4 */
  { RESERVEDFLAG_CHAR, RESERVEDFLAG_STRING },   /* Bit 3 */
  { 'H', "Hash key flag" },                     /* Bit 2 */
  { 'Q', "Inline QoS" },                        /* Bit 1 */
  { 'E', "Endianness bit" }                     /* Bit 0 */
};

static const struct Flag_definition NACK_FRAG_FLAGS[] = {
  { RESERVEDFLAG_CHAR, RESERVEDFLAG_STRING },   /* Bit 7 */
  { RESERVEDFLAG_CHAR, RESERVEDFLAG_STRING },   /* Bit 6 */
  { RESERVEDFLAG_CHAR, RESERVEDFLAG_STRING },   /* Bit 5 */
  { RESERVEDFLAG_CHAR, RESERVEDFLAG_STRING },   /* Bit 4 */
  { RESERVEDFLAG_CHAR, RESERVEDFLAG_STRING },   /* Bit 3 */
  { RESERVEDFLAG_CHAR, RESERVEDFLAG_STRING },   /* Bit 2 */
  { RESERVEDFLAG_CHAR, RESERVEDFLAG_STRING },   /* Bit 1 */
  { 'E', "Endianness bit" }                     /* Bit 0 */
};

static const struct Flag_definition RTPS_DATA_FLAGS[] = {
  { RESERVEDFLAG_CHAR, RESERVEDFLAG_STRING },   /* Bit 7 */
  { RESERVEDFLAG_CHAR, RESERVEDFLAG_STRING },   /* Bit 6 */
  { RESERVEDFLAG_CHAR, RESERVEDFLAG_STRING },   /* Bit 5 */
  { RESERVEDFLAG_CHAR, RESERVEDFLAG_STRING },   /* Bit 4 */
  { 'K', "Serialized Key"  },                   /* Bit 3 */
  { 'D', "Data present" },                      /* Bit 2 */
  { 'Q', "Inline QoS" },                        /* Bit 1 */
  { 'E', "Endianness bit" }                     /* Bit 0 */
};

static const struct Flag_definition RTPS_DATA_FRAG_FLAGS[] = {
  { RESERVEDFLAG_CHAR, RESERVEDFLAG_STRING },   /* Bit 7 */
  { RESERVEDFLAG_CHAR, RESERVEDFLAG_STRING },   /* Bit 6 */
  { RESERVEDFLAG_CHAR, RESERVEDFLAG_STRING },   /* Bit 5 */
  { RESERVEDFLAG_CHAR, RESERVEDFLAG_STRING },   /* Bit 4 */
  { RESERVEDFLAG_CHAR, RESERVEDFLAG_STRING },   /* Bit 3 */
  { 'K', "Serialized Key"  },                   /* Bit 2 */
  { 'Q', "Inline QoS" },                        /* Bit 1 */
  { 'E', "Endianness bit" }                     /* Bit 0 */
};

static const struct Flag_definition RTPS_DATA_BATCH_FLAGS[] = {
  { RESERVEDFLAG_CHAR, RESERVEDFLAG_STRING },   /* Bit 7 */
  { RESERVEDFLAG_CHAR, RESERVEDFLAG_STRING },   /* Bit 6 */
  { RESERVEDFLAG_CHAR, RESERVEDFLAG_STRING },   /* Bit 5 */
  { RESERVEDFLAG_CHAR, RESERVEDFLAG_STRING },   /* Bit 4 */
  { RESERVEDFLAG_CHAR, RESERVEDFLAG_STRING },   /* Bit 3 */
  { RESERVEDFLAG_CHAR, RESERVEDFLAG_STRING },   /* Bit 2 */
  { 'Q', "Inline QoS" },                        /* Bit 1 */
  { 'E', "Endianness bit" }                     /* Bit 0 */
};

static const struct Flag_definition RTPS_SAMPLE_INFO_FLAGS16[] = {
  { RESERVEDFLAG_CHAR, RESERVEDFLAG_STRING },   /* Bit 15 */
  { RESERVEDFLAG_CHAR, RESERVEDFLAG_STRING },   /* Bit 14 */
  { RESERVEDFLAG_CHAR, RESERVEDFLAG_STRING },   /* Bit 13 */
  { RESERVEDFLAG_CHAR, RESERVEDFLAG_STRING },   /* Bit 12 */
  { RESERVEDFLAG_CHAR, RESERVEDFLAG_STRING },   /* Bit 11 */
  { RESERVEDFLAG_CHAR, RESERVEDFLAG_STRING },   /* Bit 10 */
  { RESERVEDFLAG_CHAR, RESERVEDFLAG_STRING },   /* Bit 9 */
  { RESERVEDFLAG_CHAR, RESERVEDFLAG_STRING },   /* Bit 8 */
  { RESERVEDFLAG_CHAR, RESERVEDFLAG_STRING },   /* Bit 7 */
  { RESERVEDFLAG_CHAR, RESERVEDFLAG_STRING },   /* Bit 6 */
  { 'K', "Serialized Key" },                    /* Bit 5 */
  { 'I', "Invalid sample" },                    /* Bit 4 */
  { 'D', "Data present" },                      /* Bit 3 */
  { 'O', "OffsetSN present" },                  /* Bit 2 */
  { 'Q', "Inline QoS" },                        /* Bit 1 */
  { 'T', "Timestamp present" }                  /* Bit 0 */
};


/***************************************************************************/





/***************************************************************************
 * Function prototypes
 * ~~~~~~~~~~~~~~~~~~~
 */

/* Utility to add elements to the protocol tree */
static void rtps_util_format_ipv6(guint8 *, guint8 *, gint);
static void rtps_util_add_protocol_version(proto_tree *, tvbuff_t *, gint);
static void rtps_util_add_vendor_id(proto_tree *, tvbuff_t *,
                        gint, guint8 *, gint);
static void rtps_util_add_locator_t(proto_tree *, tvbuff_t *,
                        gint, int, const guint8 *, guint8 *, gint);
static int  rtps_util_add_locator_list(proto_tree *, tvbuff_t *,
                        gint, const guint8 *, int);
static void rtps_util_add_ipv4_address_t(proto_tree *, tvbuff_t *,
                        gint, int, const guint8 *, guint8 *, gint);
static void rtps_util_add_locator_udp_v4(proto_tree *, tvbuff_t *,
                        gint, const guint8 *, int);
static void rtps_util_add_guid_prefix(proto_tree *, tvbuff_t *,
                        gint, int, int, int, int, const guint8 *,
                        guint8 *, gint);
static void rtps_util_add_entity_id(proto_tree *, tvbuff_t *,
                        gint, int, int, int, int, const char *, guint32 *);
static void rtps_util_add_generic_entity_id(proto_tree *, tvbuff_t *,
                        gint, const char *,
                        guint8 *, gint);
static void rtps_util_add_generic_guid(proto_tree *, tvbuff_t *,
                        gint, const char *, guint8 *, gint);
static guint64 rtps_util_add_seq_number(proto_tree *, tvbuff_t *,
                        gint, int, const char *);
static void rtps_util_add_ntp_time(proto_tree *, tvbuff_t *,
                        gint, int, const char *, guint8 *, gint);
static gint rtps_util_add_string(proto_tree *, tvbuff_t *,
                        gint, int, int, const guint8 *, guint8 *, size_t);
static guint32 rtps_util_add_long(proto_tree *, tvbuff_t *,
                        gint, int, int, gboolean, gboolean, const char *,
                        guint8 *, size_t);
static guint16 rtps_util_add_short(proto_tree *, tvbuff_t *,
                        gint, int, int, gboolean, gboolean, const char *,
                        guint8 *, gint);
static void rtps_util_add_port(proto_tree *, tvbuff_t *,
                        gint, int, char *, guint8 *, gint);
static void rtps_util_add_boolean(proto_tree *, tvbuff_t *,
                        gint, char *, guint8 *, size_t);
static void rtps_util_add_durability_service_qos(proto_tree *, tvbuff_t *,
                        gint, int, guint8 *, gint);
static void rtps_util_add_liveliness_qos(proto_tree *, tvbuff_t *,
                        gint, int, guint8 *, gint);
static void rtps_util_add_kind_qos(proto_tree *, tvbuff_t *,
                        gint, int, char *, const value_string *, guint8 *, size_t);
static gint rtps_util_add_seq_string(proto_tree *, tvbuff_t *,
                        gint, int, int, char *, guint8 *, gint);
static void rtps_util_add_seq_octets(proto_tree *, tvbuff_t *,
                        gint, int, int, int, guint8 *, gint);
static int rtps_util_add_bitmap(proto_tree *, tvbuff_t *,
                        gint, int, const char *);
static int rtps_util_add_fragment_number_set(proto_tree *, tvbuff_t *,
                        gint, int, const char *, gint);
static void rtps_util_decode_flags(proto_tree *, tvbuff_t *,
                        gint, guint8, const struct Flag_definition *);
static void rtps_util_decode_flags_16bit(proto_tree *, tvbuff_t *,
                        gint, guint16, const struct Flag_definition *);
static gint rtps_util_add_seq_ulong(proto_tree *, tvbuff_t *,
                        gint, int, int, int, int, char *);
static void rtps_util_add_extra_flags(proto_tree *, tvbuff_t *,
                        gint, const char *);

/* The data (payload) dissector */
static void dissect_serialized_data(proto_tree *, tvbuff_t *,
                        gint, int, const char *, guint16 vendor_id);

static void dissect_octet_seq(proto_tree *, tvbuff_t *,
                        gint, const char *);

/* The data (payload) dissector for parameter sequences */
static gint dissect_parameter_sequence(proto_tree *, tvbuff_t *,
                        gint, int, int, const char *, guint32 *, guint16 vendor_id);




/* Sub-message dissector functions */
#define DECLARE_DISSECTOR_SUBMESSAGE(sm)    \
static void dissect_## sm (tvbuff_t *tvb, gint offset, guint8 flags,    \
                        gboolean little_endian, int next_submsg_offset, \
                        proto_tree *rtps_submessage_tree,               \
                        char *info_summary_text, guint16 vendor_id)
DECLARE_DISSECTOR_SUBMESSAGE(PAD);
DECLARE_DISSECTOR_SUBMESSAGE(DATA);
DECLARE_DISSECTOR_SUBMESSAGE(DATA_FRAG);
DECLARE_DISSECTOR_SUBMESSAGE(NOKEY_DATA);
DECLARE_DISSECTOR_SUBMESSAGE(NOKEY_DATA_FRAG);
DECLARE_DISSECTOR_SUBMESSAGE(NACK_FRAG);
DECLARE_DISSECTOR_SUBMESSAGE(ACKNACK);
DECLARE_DISSECTOR_SUBMESSAGE(HEARTBEAT);
DECLARE_DISSECTOR_SUBMESSAGE(HEARTBEAT_FRAG);
DECLARE_DISSECTOR_SUBMESSAGE(GAP);
DECLARE_DISSECTOR_SUBMESSAGE(INFO_TS);
DECLARE_DISSECTOR_SUBMESSAGE(INFO_SRC);
DECLARE_DISSECTOR_SUBMESSAGE(INFO_REPLY_IP4);
DECLARE_DISSECTOR_SUBMESSAGE(INFO_DST);
DECLARE_DISSECTOR_SUBMESSAGE(INFO_REPLY);
DECLARE_DISSECTOR_SUBMESSAGE(RTPS_DATA_FRAG);
DECLARE_DISSECTOR_SUBMESSAGE(RTPS_DATA_BATCH);
DECLARE_DISSECTOR_SUBMESSAGE(HEARTBEAT_BATCH);
/* The RTPS_DATA has an extra parameter, can't use the macro... */
static void dissect_RTPS_DATA(tvbuff_t *, gint, guint8, gboolean, int,
                proto_tree *, char *, guint16, int);
#undef DECLARE_DISSECTOR_SUBMESSAGE

/* The main packet dissector */
static gboolean dissect_rtps(tvbuff_t *, packet_info *, proto_tree *);


/***************************************************************************/
/* Inline macros                                                           */
/***************************************************************************/
#define NEXT_guint16(tvb, offset, le)    \
                (le ? tvb_get_letohs(tvb, offset) : tvb_get_ntohs(tvb, offset))

#define NEXT_guint32(tvb, offset, le)    \
                (le ? tvb_get_letohl(tvb, offset) : tvb_get_ntohl(tvb, offset))


/***************************************************************************/
/* Global variables controlled by Wireshark preference panel               */
/***************************************************************************/
static guint rtps_max_batch_samples_dissected = 16;


/* *********************************************************************** */
/* Appends a submessage description to the info summary text
 */
static void info_summary_append(char *summaryText, int submessageId, const char * extra_text) {
  gint len = (gint) strlen(summaryText);
  if (extra_text == NULL) {
    extra_text="";
  }
  if (summaryText[0] != '\0') {
    g_strlcat(summaryText, ", ", MAX_SUMMARY_SIZE-len-1);
    len += 2;
  }
  g_snprintf(summaryText + len,
                MAX_SUMMARY_SIZE - len,
                "%s%s",
                val_to_str(submessageId, submessage_id_vals, "Unknown[%02x]"),
                extra_text);
}

/* *********************************************************************** */
/* Appends a submessage description to the info summary text, with
 * extra formatting for those submessages that has a status info
 */
static void info_summary_append_ex(char *info_summary_text,
                        int submessageId,
                        guint32 writer_id,
                        guint32 status_info) {

  /* Defines the extra information associated to the writer involved in
   * this communication
   *
   * Format: [?Ptwrpm]\(u?d?\)
   *
   * First letter table:
   *
   *    writerEntityId value                            | Letter
   * ---------------------------------------------------+--------------
   * ENTITYID_UNKNOWN                                   | ?
   * ENTITYID_PARTICIPANT                               | P
   * ENTITYID_SEDP_BUILTIN_TOPIC_WRITER                 | t
   * ENTITYID_SEDP_BUILTIN_PUBLICATIONS_WRITER          | w
   * ENTITYID_SEDP_BUILTIN_SUBSCRIPTIONS_WRITER         | r
   * ENTITYID_SPDP_BUILTIN_PARTICIPANT_WRITER           | p
   * ENTITYID_P2P_BUILTIN_PARTICIPANT_MESSAGE_WRITER    | m
   *
   * The letter is followed by:
   * status_info &1 | status_info & 2       | Text
   * ---------------+-----------------------+--------------
   *  status_info not defined in inlineQos  | [?]
   *      0         |         0             | [__]
   *      0         |         1             | [u_]
   *      1         |         0             | [_d]
   *      1         |         1             | [ud]
   */
  /*                 0123456 */
  char buffer[10] = "(?[??])";

  if (writer_id == ENTITYID_PARTICIPANT)
    buffer[1] = 'P';
  else if (writer_id == ENTITYID_SEDP_BUILTIN_TOPIC_WRITER)
    buffer[1] = 't';
  else if (writer_id == ENTITYID_SEDP_BUILTIN_PUBLICATIONS_WRITER)
    buffer[1] = 'w';
  else if (writer_id == ENTITYID_SEDP_BUILTIN_SUBSCRIPTIONS_WRITER)
    buffer[1] = 'r';
  else if (writer_id == ENTITYID_SPDP_BUILTIN_PARTICIPANT_WRITER)
    buffer[1] = 'p';
  else if (writer_id == ENTITYID_P2P_BUILTIN_PARTICIPANT_MESSAGE_WRITER)
    buffer[1] = 'm';
  else {
    /* Unknown writer ID, don't format anything */
    info_summary_append(info_summary_text, submessageId, NULL);
    return;
  }

  switch(status_info) {
    case 0: buffer[3] = '_'; buffer[4] = '_'; break;
    case 1: buffer[3] = '_'; buffer[4] = 'D'; break;
    case 2: buffer[3] = 'U'; buffer[4] = '_'; break;
    case 3: buffer[3] = 'U'; buffer[4] = 'D'; break;
    default:  /* Unknown status info, omit it */
            buffer[2] = ')';
            buffer[3] = '\0';
  }
  info_summary_append(info_summary_text, submessageId, buffer);
}




/* *********************************************************************** */
/* Format the given address (16 octets) as an IPv6 address
 */
static void rtps_util_format_ipv6(guint8 *addr,
                        guint8 *buffer,
                        gint    buffer_size) {
  guint32 i;
  guint8 temp[5]; /* Contains a 4-digit hex value */

  buffer[0] = '\0';
  for (i = 0; i < 16; i+=2) {
    /* Unfortunately %x is the same thing as %02x all the time... sigh */
    g_snprintf(temp, 5, "%02x%02x", addr[i], addr[i+1]);
    if (temp[0] == '0') {
      if (temp[1] == '0') {
        if (temp[2] == '0') {
          g_strlcat(buffer, &temp[3], buffer_size);
        } else {
          g_strlcat(buffer, &temp[2], buffer_size);
        }
      } else {
        g_strlcat(buffer, &temp[1], buffer_size);
      }
    } else {
      g_strlcat(buffer, temp, buffer_size);
    }
    if (i < 14) {
      g_strlcat(buffer, ":", buffer_size);
    }
  }
}




/* !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
 * NOTE:
 * In general those utility functions (they all starts with 'rtps_util')
 * are used to dissect some part of a submessage.
 * They take as first parameter the proto_tree.
 * Now, the proto_tree can be NULL if the dissector is invoked without
 * a packet tree.
 * Sometimes those functions they also return some value (as result of
 * the dissecting).
 * At the price of optimizing the code, each function MUST tollerate
 * a NULl tree.
 * !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
 */



/* *********************************************************************** */
static void rtps_util_add_extra_flags(proto_tree *tree,
                        tvbuff_t *tvb,
                        gint offset,
                        const char *label) {
  if (tree) {
    guint16 flags = NEXT_guint16(tvb, offset, 0); /* Always big endian */
    guint8  temp_buffer[20];
    int i;
    for (i = 0; i < 16; ++i) {
      temp_buffer[i] = ((flags & (1 << (15-i))) != 0) ? '1' : '0';
    }
    temp_buffer[16] = '\0';

    proto_tree_add_text(tree,
                        tvb,
                        offset,
                        2,
                        "%s: %s",
                        label,
                        temp_buffer);
  }
}

/* *********************************************************************** */
static void rtps_util_add_protocol_version(proto_tree *tree,
                        tvbuff_t *  tvb,
                        gint        offset) {
  if (tree) {
    proto_item * ti;
    proto_tree * version_tree;

    ti = proto_tree_add_none_format(tree,
                          hf_rtps_protocol_version,
                          tvb,
                          offset,
                          2,
                          "Protocol version: %d.%d",
                          tvb_get_guint8(tvb, offset),
                          tvb_get_guint8(tvb, offset+1));
    version_tree = proto_item_add_subtree(ti,
                          ett_rtps_proto_version);
    proto_tree_add_item(version_tree,
                          hf_rtps_protocol_version_major,
                          tvb,
                          offset,
                          1,
                          FALSE);
    proto_tree_add_item(version_tree,
                          hf_rtps_protocol_version_minor,
                          tvb,
                          offset+1,
                          1,
                          FALSE);
  }
}


/* ------------------------------------------------------------------------- */
/* Interpret the next bytes as vendor ID. If proto_tree and field ID is
 * provided, it can also set.
 */
static void rtps_util_add_vendor_id(proto_tree *tree,
                        tvbuff_t * tvb,
                        gint       offset,
                        guint8 *   buffer,              /* Can be NULL */
                        gint       buffer_size) {       /* Can be 0 */
  guint8 major, minor;
  guint32 vendor_id = 0;
  guint8 vendor_name[MAX_VENDOR_ID_SIZE];

  major = tvb_get_guint8(tvb, offset);
  minor = tvb_get_guint8(tvb, offset+1);
  vendor_id = (major<<8) | minor;
  switch(vendor_id) {
    case RTPS_VENDOR_UNKNOWN:
      g_strlcpy(vendor_name, RTPS_VENDOR_UNKNOWN_STRING, MAX_VENDOR_ID_SIZE);
      break;

    case RTPS_VENDOR_RTI:
      g_strlcpy(vendor_name, RTPS_VENDOR_RTI_STRING, MAX_VENDOR_ID_SIZE);
      break;

    case RTPS_VENDOR_TOC:
      g_strlcpy(vendor_name, RTPS_VENDOR_TOC_STRING, MAX_VENDOR_ID_SIZE);
      break;

    default:
      g_snprintf(vendor_name, MAX_VENDOR_ID_SIZE, "%d.%d", major, minor);
  }

  if (tree) {
    proto_tree_add_uint_format(tree,
                        hf_rtps_vendor_id,
                        tvb,
                        offset,
                        2,
                        vendor_id,
                        "vendor: %s",
                        vendor_name);
  }
  if (buffer != NULL) {
    g_strlcpy(buffer, vendor_name, buffer_size);
  }
}



/* ------------------------------------------------------------------------- */
/* Insert in the protocol tree the next 8 bytes interpreted as Locator_t
 *
 * Locator_t is a struct defined as:
 * struct {
 *    long kind;                // kind of locator
 *    unsigned long port;
 *    octet[16] address;
 * } Locator_t;
 */
static void rtps_util_add_locator_t(proto_tree *tree,
                        tvbuff_t * tvb,
                        gint       offset,
                        int        little_endian,
                        const guint8 * label,
                        guint8 *   buffer,              /* Can be NULL */
                        gint       buffer_size) {       /* Can be 0 */

  proto_item * ti;
  proto_tree * locator_tree;
  gint32  kind;
  guint8  addr[16];
  guint32 port;
  char temp_buff[MAX_LOCATOR_SIZE];
  char addr_buff[MAX_IPV6_SIZE];
  const char *kind_string = NULL;
  int i;


  kind    = NEXT_guint32(tvb, offset, little_endian);
  port = NEXT_guint32(tvb, offset+4, little_endian);
  for (i = 0; i < 16; ++i) {
    addr[i] = tvb_get_guint8(tvb, offset + 8 + i);
  }


  switch(kind) {
    case LOCATOR_KIND_UDPV4:
        kind_string = "LOCATOR_KIND_UDPV4";
        g_snprintf(addr_buff, MAX_IPV6_SIZE,
                        "%d.%d.%d.%d",
                        addr[12],
                        addr[13],
                        addr[14],
                        addr[15]);
        g_snprintf(temp_buff, MAX_LOCATOR_SIZE, "%s:%d",
                        addr_buff,
                        port);
        break;

    case LOCATOR_KIND_UDPV6:
        kind_string = "LOCATOR_KIND_UDPV6";
        rtps_util_format_ipv6(addr, &addr_buff[0], MAX_IPV6_SIZE);
        g_snprintf(temp_buff, MAX_LOCATOR_SIZE,
                        "IPv6: { addr=%s, port=%d }",
                        addr_buff,
                        port);
        break;

    case LOCATOR_KIND_INVALID:
        kind_string = "LOCATOR_KIND_INVALID";

    case LOCATOR_KIND_RESERVED:
        if (!kind_string)  /* Need to guard overrides (no break before) */
          kind_string = "LOCATOR_KIND_RESERVED";

    default:
        if (!kind_string)  /* Need to guard overrides (no break before) */
          kind_string = "(unknown)";
        g_snprintf(temp_buff, MAX_LOCATOR_SIZE,
                        "{ kind=%02x, port=%d, addr=%02x %02x %02x ... %02x %02x }",
                        kind,
                        port,
                        addr[0],
                        addr[1],
                        addr[2],
                        /* ... */
                        addr[14],
                        addr[15]);
  }
  if (tree) {
    ti = proto_tree_add_text(tree,
                        tvb,
                        offset,
                        24,
                        "%s: %s",
                        label,
                        temp_buff);

    locator_tree = proto_item_add_subtree(ti,
                        ett_rtps_locator);
    proto_tree_add_text(locator_tree,
                        tvb,
                        offset,
                        4,
                        "kind: %02x (%s)",
                        kind,
                        kind_string);
    proto_tree_add_text(locator_tree,
                        tvb,
                        offset+4,
                        4,
                        "port: %d%s",
                        port,
                        (port == 0) ? " (PORT_INVALID)" : "");
    proto_tree_add_text(locator_tree,
                        tvb,
                        offset + 8,
                        16,
                        "address: %s",
                        addr_buff);
  }
  if (buffer) {
    g_strlcpy(buffer, temp_buff, buffer_size);
  }
}

/* ------------------------------------------------------------------------- */
/* Insert in the protocol tree the next bytes interpreted as a list of
 * Locators:
 *   - unsigned long numLocators
 *   - locator 1
 *   - locator 2
 *   - ...
 *   - locator n
 * Returns the new offset after parsing the locator list
 */
static int rtps_util_add_locator_list(proto_tree *tree,
                        tvbuff_t * tvb,
                        gint       offset,
                        const guint8 * label,
                        int        little_endian) {

  proto_item *ti;
  proto_tree *locator_tree;
  guint32 num_locators;

  num_locators = NEXT_guint32(tvb, offset, little_endian);
  if (tree) {
    ti = proto_tree_add_text(tree,
                        tvb,
                        offset,
                        4,
                        "%s: %d Locators",
                        label,
                        num_locators);
  } else {
    return offset + 4 + ((num_locators > 0) ? (24 * num_locators) : 0);
  }
  offset += 4;
  if (num_locators > 0) {
    guint32 i;
    char temp_buff[20];

    locator_tree = proto_item_add_subtree(ti,
                        ett_rtps_locator_udp_v4);

    for (i = 0; i < num_locators; ++i) {
      g_snprintf(temp_buff, 20, "Locator[%d]", i);
      rtps_util_add_locator_t(locator_tree,
                        tvb,
                        offset,
                        little_endian,
                        temp_buff,
                        NULL,
                        0);
      offset += 24;
    }
  }
  return offset;
}


/* ------------------------------------------------------------------------- */
/* Insert in the protocol tree the next 4 bytes interpreted as IPV4Address_t
 */
static void rtps_util_add_ipv4_address_t(proto_tree *tree,
                        tvbuff_t * tvb,
                        gint       offset,
                        int        little_endian,
                        const guint8 * label,
                        guint8 *   buffer,              /* Can be NULL */
                        gint       buffer_size) {       /* Can be 0 */

  guint32 addr;

  addr = NEXT_guint32(tvb, offset, little_endian);
  if (addr == IPADDRESS_INVALID) {
    if (buffer) {
      g_strlcpy(buffer, IPADDRESS_INVALID_STRING, buffer_size);
    }
    if (tree) {
      proto_tree_add_text(tree,
                        tvb,
                        offset,
                        4,
                        "%s: %s",
                        label,
                        IPADDRESS_INVALID_STRING);
    }
  } else {
    if (buffer) {
      g_snprintf(buffer, buffer_size,
                        "%d.%d.%d.%d",
                        (addr >> 24) & 0xff,
                        (addr >> 16) & 0xff,
                        (addr >> 8) & 0xff,
                        addr & 0xff);
    }
    if (tree) {
      proto_tree_add_text(tree,
                        tvb,
                        offset,
                        4,
                        "%s: %d.%d.%d.%d",
                        label,
                        (addr >> 24) & 0xff,
                        (addr >> 16) & 0xff,
                        (addr >> 8) & 0xff,
                        addr & 0xff);
    }
  }
}



/* ------------------------------------------------------------------------- */
/* Insert in the protocol tree the next 8 bytes interpreted as LocatorUDPv4
 *
 * LocatorUDPv4 is a struct defined as:
 * struct {
 *    unsigned long address;
 *    unsigned long port;
 * } LocatorUDPv4_t;
 *
 */
static void rtps_util_add_locator_udp_v4(proto_tree *tree,
                        tvbuff_t * tvb,
                        gint       offset,
                        const guint8 * label,
                        int        little_endian) {
  if (tree) {
    proto_item * ti;
    proto_tree * locator_tree;
    guint32 port;
    char portLabel[MAX_PORT_SIZE];
    char addr[MAX_IPV4_ADDRESS_SIZE];

    port = NEXT_guint32(tvb, offset+4, little_endian);

    if (port == PORT_INVALID) {
      g_snprintf(portLabel, MAX_PORT_SIZE, "%s (0x00000000)", PORT_INVALID_STRING);
    } else {
      g_snprintf(portLabel, MAX_PORT_SIZE, "%u", port);
    }

    ti = proto_tree_add_text(tree,
                          tvb,
                          offset,
                          8,
                          "addr"); /* Add text later */
    locator_tree = proto_item_add_subtree(ti, ett_rtps_locator_udp_v4);
    rtps_util_add_ipv4_address_t(locator_tree,
                          tvb,
                          offset,
                          little_endian,
                          "address",
                          addr,
                          MAX_IPV4_ADDRESS_SIZE);
    proto_tree_add_text(locator_tree,
                          tvb,
                          offset + 4,
                          4,
                          "port: %s",
                          portLabel);

    proto_item_set_text(ti, "%s: { address=%s, port=%s }",
                          label,
                          addr,
                          portLabel);
  }
}


/* ------------------------------------------------------------------------- */
/* Insert in the protocol tree the next 12 bytes interpreted as GuidPrefix
 * If tree is specified, it fills up the protocol tree item:
 *  - hf_rtps_guid_prefix
 *  - hf_rtps_host_id
 *  - hf_rtps_app_id
 *  - hf_rtps_counter
 *
 * If buffer is specified, it returns in it a string representation of the
 * data read.
 */
static void rtps_util_add_guid_prefix(proto_tree *tree,
                        tvbuff_t * tvb,
                        gint       offset,
                        int        hf_prefix,           /* Cannot be 0 if tree != NULL */
                        int        hf_host_id,
                        int        hf_app_id,
                        int        hf_counter,
                        const guint8 * label,           /* Can be NULL */
                        guint8 *   buffer,              /* Can be NULL */
                        gint       buffer_size) {
  guint32  host_id;
  guint32  app_id;
  guint32  counter;
  guint8 * temp_buff;
  guint8   guid_prefix[12];
  const guint8 * safe_label;
  int i;

  safe_label = (label == NULL) ? (const guint8 *)"guidPrefix" : label;

  /* Read values from TVB */
  host_id   = tvb_get_ntohl(tvb, offset);
  app_id    = tvb_get_ntohl(tvb, offset + 4);
  counter   = tvb_get_ntohl(tvb, offset + 8);
  for (i = 0; i < 12; ++i) {
    guid_prefix[i] = tvb_get_guint8(tvb, offset+i);
  }

  /* Format the string */
  temp_buff = (guint8 *) ep_alloc(MAX_GUID_PREFIX_SIZE);
  g_snprintf(temp_buff, MAX_GUID_PREFIX_SIZE,
                        "%s=%02x%02x%02x%02x:%02x%02x%02x%02x:%02x%02x%02x%02x"
                        " { hostId=%08x, appId=%08x, counter=%08x }",
                        safe_label,
                        guid_prefix[0],
                        guid_prefix[1],
                        guid_prefix[2],
                        guid_prefix[3],
                        guid_prefix[4],
                        guid_prefix[5],
                        guid_prefix[6],
                        guid_prefix[7],
                        guid_prefix[8],
                        guid_prefix[9],
                        guid_prefix[10],
                        guid_prefix[11],
                        host_id,
                        app_id,
                        counter);

  if (tree) {
    proto_item * ti, *hidden_item;
    proto_tree * guid_tree;

    /* The numeric value (used for searches) */
    hidden_item = proto_tree_add_item(tree,
                        hf_prefix,
                        tvb,
                        offset,
                        12,
                        FALSE);
    PROTO_ITEM_SET_HIDDEN(hidden_item);

    /* The text node (root of the guid prefix sub-tree) */
    ti = proto_tree_add_text(tree,
                        tvb,
                        offset,
                        12,
                        "%s",
                        temp_buff);

    guid_tree = proto_item_add_subtree(ti,
                        ett_rtps_guid_prefix);

    /* Host Id */
    proto_tree_add_item(guid_tree,
                        hf_host_id,
                        tvb,
                        offset,
                        4,
                        FALSE);

    /* App Id */
    proto_tree_add_item(guid_tree,
                        hf_app_id,
                        tvb,
                        offset+4,
                        4,
                        FALSE);

    /* Counter */
    proto_tree_add_item(guid_tree,
                        hf_counter,
                        tvb,
                        offset+8,
                        4,
                        FALSE);
  }

  if (buffer != NULL) {
    g_strlcpy(buffer, temp_buff, buffer_size);
  }
}



/* ------------------------------------------------------------------------- */
 /* Insert the entityId from the next 4 bytes. Since there are more than
  * one entityId, we need to specify also the IDs of the entityId (and its
  * sub-components), as well as the label identifying it.
  */
static void rtps_util_add_entity_id(proto_tree *tree,
                        tvbuff_t * tvb,
                        gint       offset,
                        int        hf_item,
                        int        hf_item_entity_key,
                        int        hf_item_entity_kind,
                        int        subtree_entity_id,
                        const char *label,
                        guint32 *  entity_id_out) {             /* Can be NULL */
  guint32 entity_id   = tvb_get_ntohl(tvb, offset);
  guint32 entity_key  = (entity_id >> 8);
  guint8  entity_kind = (entity_id & 0xff);
  const char *str_predef = match_strval(entity_id, entity_id_vals);

  if (entity_id_out != NULL) {
    *entity_id_out = entity_id;
  }


  if (tree) {
    proto_tree * entity_tree;
    proto_item * ti;

    if (str_predef == NULL) {
      /* entityId is not a predefined value, format it */
      ti = proto_tree_add_uint_format(tree,
                        hf_item,
                        tvb,
                        offset,
                        4,
                        entity_id,
                        "%s: 0x%08x (%s: 0x%06x)",
                        label,
                        entity_id,
                        val_to_str(entity_kind, entity_kind_vals,
                                        "unknown kind (%02x)"),
                        entity_key);
    } else {
      /* entityId is a predefined value */
      ti = proto_tree_add_uint_format(tree,
                        hf_item,
                        tvb,
                        offset,
                        4,
                        entity_id,
                        "%s: %s (0x%08x)", label, str_predef, entity_id);
    }

    entity_tree = proto_item_add_subtree(ti,
                        subtree_entity_id);

    proto_tree_add_item(entity_tree,
                        hf_item_entity_key,
                        tvb,
                        offset,
                        3,
                        FALSE);

    proto_tree_add_item(entity_tree,
                        hf_item_entity_kind,
                        tvb,
                        offset+3,
                        1,
                        FALSE);

  }
}

/* ------------------------------------------------------------------------- */
 /* Insert the entityId from the next 4 bytes as a generic one (not connected
  * to any protocol field). It simply insert the content as a simple text entry
  * and returns in the passed buffer only the value (without the label).
  */
static void rtps_util_add_generic_entity_id(proto_tree *tree,
                        tvbuff_t * tvb,
                        gint       offset,
                        const char *label,
                        guint8 *   buffer,                      /* Can be NULL */
                        gint       buffer_size) {
  guint32 entity_id   = tvb_get_ntohl(tvb, offset);
  guint32 entity_key  = (entity_id >> 8);
  guint8  entity_kind = (entity_id & 0xff);
  const char *str_predef = match_strval(entity_id, entity_id_vals);
  guint8  temp_buffer[MAX_GUID_SIZE];

  if (str_predef == NULL) {
    /* entityId is not a predefined value, format it */
    g_snprintf(temp_buffer, MAX_GUID_SIZE,
                        "0x%08x (%s: 0x%06x)",
                        entity_id,
                        val_to_str(entity_kind, entity_kind_vals,
                                      "unknown kind (%02x)"),
                        entity_key);
  } else {
    /* entityId is a predefined value */
    g_snprintf(temp_buffer, MAX_GUID_SIZE,
                        "%s (0x%08x)",
                        str_predef,
                        entity_id);
  }

  if (tree) {
      proto_tree_add_text(tree,
                        tvb,
                        offset,
                        4,
                        "%s: %s",
                        label,
                        temp_buffer);
  }

  if (buffer != NULL) {
      g_strlcpy(buffer, temp_buffer, buffer_size);
  }
}



/* ------------------------------------------------------------------------- */
 /* Interpret the next 16 octets as a generic GUID and insert it in the protocol
  * tree as simple text (no reference fields are set).
  * It is mostly used in situation where is not required to perform search for
  * this kind of GUID (i.e. like in some DATA parameter lists).
  */
static void rtps_util_add_generic_guid(proto_tree *tree,
                        tvbuff_t * tvb,                         /* Cannot be NULL */
                        gint       offset,
                        const char *label,                      /* Cannot be NULL */
                        guint8 *   buffer,                      /* Can be NULL */
                        gint       buffer_size) {

  guint32 host_id;
  guint32 app_id;
  guint32 entity_id;
  guint32 entity_key;
  guint32 counter;
  guint8  entity_kind;
  guint8  guid_raw[16];
  const char * str_entity_kind;
  guint8 temp_buff[MAX_GUID_SIZE];
  int i;

  /* Read typed data */
  host_id   = tvb_get_ntohl(tvb, offset);
  app_id    = tvb_get_ntohl(tvb, offset + 4);
  counter   = tvb_get_ntohl(tvb, offset + 8);
  entity_id = tvb_get_ntohl(tvb, offset + 12);

  /* Re-Read raw data */
  for (i = 0; i < 16; ++i) {
    guid_raw[i] = tvb_get_guint8(tvb, offset+i);
  }

  /* Split components from typed data */
  entity_key  = (entity_id >> 8);
  entity_kind = (entity_id & 0xff);

  /* Lookup for predefined app kind and entity kind */
  str_entity_kind = val_to_str(entity_kind, entity_kind_vals, "%02x");

  /* Compose output buffer for raw guid */
  g_snprintf(temp_buff, MAX_GUID_SIZE,
                        "%s=%02x%02x%02x%02x %02x%02x%02x%02x %02x%02x%02x%02x %02x%02x%02x%02x: "
                        "{ hostId=%08x, appId=%08x, counter=%08x, entityId=%08x (%s: %06x) }",
                        label,
                        guid_raw[0], guid_raw[1], guid_raw[2], guid_raw[3],
                        guid_raw[4], guid_raw[5], guid_raw[6], guid_raw[7],
                        guid_raw[8], guid_raw[9], guid_raw[10], guid_raw[11],
                        guid_raw[12], guid_raw[13], guid_raw[14], guid_raw[15],
                        host_id,
                        app_id,
                        counter,
                        entity_id, str_entity_kind, entity_key);
  if (tree) {
    proto_tree_add_text(tree, tvb, offset, 16, "%s", temp_buff);
  }
  if (buffer != NULL) {
    g_strlcpy(buffer, temp_buff, buffer_size);
  }
}


/* ------------------------------------------------------------------------- */
/* Insert in the protocol tree the next 8 bytes interpreted as sequence
 * number.
 */
static guint64 rtps_util_add_seq_number(proto_tree *tree,
                        tvbuff_t * tvb,
                        gint       offset,
                        int        little_endian,
                        const char *label _U_) {
  guint64 hi = (guint64)NEXT_guint32(tvb, offset, little_endian);
  guint64 lo = (guint64)NEXT_guint32(tvb, offset+4, little_endian);
  guint64 all = (hi << 32) | lo;

  if (tree) {
    proto_tree_add_int64_format(tree,
                        hf_rtps_sm_seq_number,
                        tvb,
                        offset,
                        8,
                        all,
                        "%s: %" G_GINT64_MODIFIER "u", label, all);
  }
  return all;
}


/* ------------------------------------------------------------------------- */
/* Insert in the protocol tree the next 8 bytes interpreted as NtpTime
 */
static void rtps_util_add_ntp_time(proto_tree *tree,
                        tvbuff_t * tvb,
                        gint       offset,
                        int        little_endian,
                        const char * label,
                        guint8 *   buffer,              /* Can be NULL */
                        gint       buffer_size) {
  guint8  tempBuffer[MAX_NTP_TIME_SIZE];

  gint32 sec = NEXT_guint32(tvb, offset, little_endian);
  guint32 frac = NEXT_guint32(tvb, offset+4, little_endian);
  double absolute;

  if ((sec == 0x7fffffff) && (frac == 0xffffffff)) {
    g_strlcpy(tempBuffer, "INFINITE", MAX_NTP_TIME_SIZE);
  } else if ((sec == 0) && (frac == 0)) {
    g_strlcpy(tempBuffer, "0 sec", MAX_NTP_TIME_SIZE);
  } else {
    absolute = (double)sec + (double)frac / ((double)(0x80000000) * 2.0);
    g_snprintf(tempBuffer, MAX_NTP_TIME_SIZE,
                        "%f sec (%ds + 0x%08x)", absolute, sec, frac);
  }
  if (tree) {
    proto_item * ti;
    proto_tree *time_tree;

    ti = proto_tree_add_none_format(tree,
                        hf_rtps_param_ntpt,
                        tvb,
                        offset,
                        8,
                        "%s: %s",
                        label,
                        tempBuffer);
    time_tree = proto_item_add_subtree(ti, ett_rtps_ntp_time);
    proto_tree_add_item(time_tree,
                        hf_rtps_param_ntpt_sec,
                        tvb,
                        offset,
                        4,
                        little_endian);
    proto_tree_add_item(time_tree,
                        hf_rtps_param_ntpt_fraction,
                        tvb,
                        offset+4,
                        4,
                        little_endian);
  }
  if (buffer != NULL) {
    g_strlcpy(buffer, tempBuffer, buffer_size);
  }
}

/* ------------------------------------------------------------------------- */
/* Insert in the protocol tree the next data interpreted as a String
 * Returns the new offset (after reading the string)
 */
static gint rtps_util_add_string(proto_tree *tree,
                        tvbuff_t * tvb,
                        gint       offset,
                        int        hf_item,             /* Can be -1 (if label!=NULL) */
                        int        little_endian,
                        const guint8 * label,           /* Can be NULL (if hf_item!=-1) */
                        guint8 *   buffer,              /* Can be NULL */
                        size_t     buffer_size) {
  guint8 * retVal = NULL;
  guint32 size = NEXT_guint32(tvb, offset, little_endian);

  if (size > 0) {
    retVal = tvb_get_ephemeral_string(tvb, offset+4, size);
  }

  if (tree) {
    if (hf_item != -1) {
      proto_item * hidden_item;
      hidden_item = proto_tree_add_string(tree,
                        hf_item,
                        tvb,
                        offset,
                        size+4,
                        (size == 0) ? (guint8 *)"" : retVal);
      PROTO_ITEM_SET_HIDDEN(hidden_item);
    }
    proto_tree_add_text(tree,
                        tvb,
                        offset,
                        size+4,
                        "%s: \"%s\"",
                        ((label != NULL) ? label : (const guint8 *)"value") ,
                        (size == 0) ? (guint8 *)"" : retVal);
  }
  if (buffer != NULL) {
    if (size == 0) {
        buffer[0] = '\0';
    } else {
      g_snprintf(buffer, (gulong) buffer_size, "%s", retVal);
    }
  }

  /* NDDS align strings at 4-bytes word. So:
   *  string_length: 4 -> buffer_length = 4;
   *  string_length: 5 -> buffer_length = 8;
   *  string_length: 6 -> buffer_length = 8;
   *  string_length: 7 -> buffer_length = 8;
   *  string_length: 8 -> buffer_length = 8;
   * ...
   */
  return offset + 4 + ((size + 3) & 0xfffffffc);
}


/* ------------------------------------------------------------------------- */
/* Insert in the protocol tree the next data interpreted as a signed long.
 * Returns the value inserted as a guint32
 */
static guint32 rtps_util_add_long(proto_tree *tree,
                        tvbuff_t * tvb,
                        gint       offset,
                        int        hf_item,             /* Can be -1 */
                        int        little_endian,
                        gboolean   is_hex,              /* Format as 0x... */
                        gboolean   is_signed,           /* Signed/Unsigned */
                        const char *label,              /* Can be NULL */
                        guint8 *   buffer,
                        size_t     buffer_size) {

  char temp_buff[16];

  guint32 retVal = NEXT_guint32(tvb, offset, little_endian);
  g_snprintf(temp_buff, 16,
                        (is_hex ? "0x%08x" : (is_signed ? "%d" : "%u")),
                        NEXT_guint32(tvb, offset, little_endian));
  if (tree != NULL) {
    if (hf_item != -1) {
      proto_tree_add_item(tree,
                        hf_item,
                        tvb,
                        offset,
                        4,
                        little_endian);
    } else if (label != NULL) {
      proto_tree_add_text(tree,
                        tvb,
                        offset,
                        4,
                        "%s: %s",
                        label,
                        temp_buff);
    }
  }
  if (buffer != NULL) {
    g_strlcpy(buffer, temp_buff, (gulong) buffer_size);
  }
  return retVal;
}

/* ------------------------------------------------------------------------- */
/* Insert in the protocol tree the next data interpreted as a 16-bit short
 */
static guint16 rtps_util_add_short(proto_tree *tree,
                        tvbuff_t * tvb,
                        gint       offset,
                        int        hf_item,             /* Can be -1 */
                        int        little_endian,
                        gboolean   is_hex,              /* Format as 0x... */
                        gboolean   is_signed,           /* Signed/Unsigned */
                        const char *label,              /* Can be NULL */
                        guint8 *   buffer,
                        gint       buffer_size) {

  char temp_buff[16];
  guint16 retVal = NEXT_guint16(tvb, offset, little_endian);
  g_snprintf(temp_buff, 16,
                        (is_hex ? "0x%04x" : (is_signed ? "%d" : "%u")),
                        retVal);
  if (tree != NULL) {
    if (hf_item != -1) {
      proto_tree_add_item(tree,
                        hf_item,
                        tvb,
                        offset,
                        2,
                        little_endian);
    } else if (label != NULL) {
      proto_tree_add_text(tree,
                        tvb,
                        offset,
                        2,
                        "%s: %s",
                        label,
                        temp_buff);
    }
  }
  if (buffer != NULL) {
    g_strlcpy(buffer, temp_buff, buffer_size);
  }
  return retVal;
}



/* ------------------------------------------------------------------------- */
/* Insert in the protocol tree the next data interpreted as a port (unsigned
 * 32-bit integer)
 */
static void rtps_util_add_port(proto_tree *tree,
                        tvbuff_t * tvb,
                        gint       offset,
                        int        little_endian,
                        char *     label,
                        guint8 *   buffer,              /* Can be NULL */
                        gint       buffer_size) {
  guint8 tempBuffer[MAX_PORT_SIZE];
  guint32 value = NEXT_guint32(tvb, offset, little_endian);

  if (value == PORT_INVALID) {
    g_snprintf(buffer, buffer_size, "%s (0x00000000)", PORT_INVALID_STRING);
  } else {
    g_snprintf(tempBuffer, MAX_PORT_SIZE, "%u", value);
  }

  if (tree != NULL) {
    proto_tree_add_text(tree,
                        tvb,
                        offset,
                        4,
                        "%s: %s",
                        label,
                        tempBuffer);
  }
  if (buffer != NULL) {
    g_strlcpy(buffer, tempBuffer, buffer_size);
  }
}


/* ------------------------------------------------------------------------- */
/* Insert in the protocol tree the next data interpreted as a boolean
 * Returns the pointer to a dynamically allocated buffer containing the
 * formatted version of the value.
 */
static void rtps_util_add_boolean(proto_tree *tree,
                        tvbuff_t * tvb,
                        gint       offset,
                        char *     label,
                        guint8 *   buffer,              /* Can be NULL */
                        size_t     buffer_size) {
  const char *str;
  guint8 value = tvb_get_guint8(tvb, offset);

  str = value ? "TRUE" : "FALSE";

  if (buffer) {
    g_strlcpy(buffer, str, (gulong) buffer_size);
  }

  if (tree) {
    proto_tree_add_text(tree,
                        tvb,
                        offset,
                        1,
                        "%s: %s",
                        label,
                        str);
  }
}


/* ------------------------------------------------------------------------- */
/* Insert in the protocol tree the next bytes interpreted as
 * DurabilityServiceQosPolicy
 */
static void rtps_util_add_durability_service_qos(proto_tree *tree,
                        tvbuff_t * tvb,
                        gint       offset,
                        int        little_endian,
                        guint8 *   buffer,
                        gint       buffer_size) {
  guint8 temp_buffer[MAX_NTP_TIME_SIZE];
  gint32 kind  = NEXT_guint32(tvb, offset+8, little_endian);
  gint32 history_depth = NEXT_guint32(tvb, offset+12, little_endian);
  gint32 max_samples   = NEXT_guint32(tvb, offset+16, little_endian);
  gint32 max_instances = NEXT_guint32(tvb, offset+20, little_endian);
  gint32 max_spi       = NEXT_guint32(tvb, offset+24, little_endian);

  rtps_util_add_ntp_time(NULL,
                        tvb,
                        offset,
                        little_endian,
                        NULL,
                        temp_buffer,
                        MAX_NTP_TIME_SIZE);

  g_snprintf(buffer, buffer_size,
                        "{ service_cleanup_delay=%s, history_kind='%s', "
                        "history_depth=%d, max_samples=%d, max_instances=%d, "
                        "max_samples_per_instances=%d }",
                        temp_buffer,
                        val_to_str(kind, history_qos_vals, "0x%08x"),
                        history_depth,
                        max_samples,
                        max_instances,
                        max_spi);
  if (tree) {
    rtps_util_add_ntp_time(tree,
                        tvb,
                        offset,
                        little_endian,
                        "service_cleanup_delay",
                        NULL,
                        0);
    proto_tree_add_text(tree,
                        tvb,
                        offset+8,
                        4,
                        "history_kind: %s",
                        val_to_str(kind, history_qos_vals, "0x%08x"));
    proto_tree_add_text(tree,
                        tvb,
                        offset+12,
                        4,
                        "history_depth: %d",
                        history_depth);
    proto_tree_add_text(tree,
                        tvb,
                        offset+16,
                        4,
                        "max_samples: %d",
                        max_samples);
    proto_tree_add_text(tree,
                        tvb,
                        offset+20,
                        4,
                        "max_instances: %d",
                        max_instances);
    proto_tree_add_text(tree,
                        tvb,
                        offset+24,
                        4,
                        "max_samples_per_instances: %d",
                        max_spi);
  }
}

/* ------------------------------------------------------------------------- */
/* Insert in the protocol tree the next bytes interpreted as Liveliness
 * QoS Policy structure.
 */
static void rtps_util_add_liveliness_qos(proto_tree *tree,
                        tvbuff_t * tvb,
                        gint       offset,
                        int        little_endian,
                        guint8 *   buffer,
                        gint       buffer_size) {
  guint8  temp_buffer[MAX_NTP_TIME_SIZE];
  guint32 kind = NEXT_guint32(tvb, offset, little_endian);

  rtps_util_add_ntp_time(NULL,
                        tvb,
                        offset+4,
                        little_endian,
                        NULL,
                        temp_buffer,
                        MAX_NTP_TIME_SIZE);

  g_snprintf(buffer, buffer_size,
                    "{ kind=%s, lease_duration=%s }",
                    val_to_str(kind, liveliness_qos_vals, "0x%08x"),
                    temp_buffer);
  if (tree) {
    proto_tree_add_text(tree,
                        tvb,
                        offset,
                        4,
                        "kind: %s",
                        val_to_str(kind, liveliness_qos_vals, "0x%08x"));
    rtps_util_add_ntp_time(tree,
                        tvb,
                        offset+4,
                        little_endian,
                        "lease_duration",
                        NULL,
                        0);
  }
}

/* ------------------------------------------------------------------------- */
/* Insert in the protocol tree the next bytes interpreted as enum type.
 */
static void rtps_util_add_kind_qos(proto_tree *tree,
                        tvbuff_t * tvb,
                        gint       offset,
                        int        little_endian,
                        char *     label,
                        const value_string *vals,
                        guint8 *   buffer,              /* Can be NULL */
                        size_t     buffer_size) {
  guint32 kind = NEXT_guint32(tvb, offset, little_endian);

  if (buffer) {
    g_strlcpy(buffer, val_to_str(kind, vals, "0x%08x"),
                        (gulong) buffer_size);
  }

  if (tree) {
    proto_tree_add_text(tree,
                        tvb,
                        offset,
                        4,
                        "%s: %s",
                        label,
                        buffer);
  }
}


/* ------------------------------------------------------------------------- */
/* Insert in the protocol tree the next bytes interpreted as Sequence of
 * Strings.
 * The formatted buffer is: "string1", "string2", "string3", ...
 * Returns the new updated offset
 */
static gint rtps_util_add_seq_string(proto_tree *tree,
                        tvbuff_t * tvb,
                        gint       offset,
                        int        little_endian,
                        int        param_length,
                        char *     label,
                        guint8 *   buffer,              /* Can NOT be NULL */
                        gint       buffer_size) {
  guint32 num_strings;
  guint32 i;
  proto_tree *string_tree = NULL;
  proto_item *ti = NULL;
  char temp_buff[MAX_LABEL_SIZE];
  guint8 overview_buffer[MAX_LABEL_SIZE];

  num_strings = NEXT_guint32(tvb, offset, little_endian);
  proto_tree_add_text(tree,
                        tvb,
                        offset,
                        4,
                        "size: %d", num_strings);
  offset += 4;

  /* Create the string node with a fake string, then replace it later */
  if (tree) {
    ti = proto_tree_add_text(tree,
                        tvb,
                        offset,
                        param_length-8,
                        "Strings");
    string_tree = proto_item_add_subtree(ti, ett_rtps_seq_string);
  }

  overview_buffer[0] = '\0';

  for (i = 0; i < num_strings; ++i) {
    g_snprintf(temp_buff, MAX_LABEL_SIZE,
                        "%s[%d]",
                        label,
                        i);
    /* This call safe with string_tree=NULL and is required to calculate offset */
    offset = rtps_util_add_string(string_tree,
                        tvb,
                        offset,
                        -1,
                        little_endian,
                        temp_buff,
                        overview_buffer+strlen(overview_buffer),
                        MAX_LABEL_SIZE-strlen(overview_buffer));
  }
  if (tree) {
    proto_item_set_text(ti,
                        "%s: %s",
                        label,
                        overview_buffer);
  }
  if (buffer != NULL) {
    g_strlcpy(buffer, overview_buffer, buffer_size);
  }
  return offset;
}

/* ------------------------------------------------------------------------- */
/* Insert in the protocol tree the next bytes interpreted as Sequence of
 * longs.
 * The formatted buffer is: val1, val2, val3, ...
 * Returns the new updated offset
 */
static gint rtps_util_add_seq_ulong(proto_tree *tree,
                        tvbuff_t * tvb,
                        gint       offset,
                        int        little_endian,
                        int        param_length,
                        int        is_hex,
                        int        is_signed,
                        char *     label) {
  guint32 num_elem;
  guint32 i;
  proto_tree *string_tree;
  proto_item *ti;
  char temp_buff[MAX_LABEL_SIZE];
  char overview_buff[MAX_PARAM_SIZE];

  num_elem = NEXT_guint32(tvb, offset, little_endian);
  offset += 4;

  /* Create the string node with an empty string, the replace it later */
  if (tree) {
    ti = proto_tree_add_text(tree,
                        tvb,
                        offset,
                        param_length-8,
                        "Seq");
    string_tree = proto_item_add_subtree(ti, ett_rtps_seq_ulong);
  } else {
    return offset + 4*num_elem;
  }

  overview_buff[0] = '\0';

  for (i = 0; i < num_elem; ++i) {
    g_snprintf(temp_buff, MAX_LABEL_SIZE,
                        "%s[%d]",
                        label,
                        i);
    rtps_util_add_long( string_tree,
                        tvb,
                        offset,
                        -1,
                        little_endian,
                        is_hex,
                        is_signed,
                        temp_buff,
                        overview_buff+strlen(overview_buff),
                        MAX_PARAM_SIZE-strlen(overview_buff));
    offset += 4;
  }
  proto_item_set_text(ti,
                        "%s: %s",
                        label,
                        overview_buff);
  return offset;
}


#define LONG_ALIGN(x)   (x = (x+3)&0xfffffffc)
#define SHORT_ALIGN(x)  (x = (x+1)&0xfffffffe)
#define MAX_ARRAY_DIMENSION 10
#define KEY_COMMENT     ("  //@key")

/* ------------------------------------------------------------------------- */
static const char * rtps_util_typecode_id_to_string(guint32 typecode_id) {
    switch(typecode_id) {
        case RTI_CDR_TK_ENUM:   return "enum";
        case RTI_CDR_TK_UNION:  return "union";
        case RTI_CDR_TK_STRUCT: return "struct";
        case RTI_CDR_TK_LONG:   return "long";
        case RTI_CDR_TK_SHORT:  return "short";
        case RTI_CDR_TK_USHORT: return "unsigned short";
        case RTI_CDR_TK_ULONG:  return "unsigned long";
        case RTI_CDR_TK_FLOAT:  return "float";
        case RTI_CDR_TK_DOUBLE: return "double";
        case RTI_CDR_TK_BOOLEAN:return "boolean";
        case RTI_CDR_TK_CHAR:   return "char";
        case RTI_CDR_TK_OCTET:  return "octet";
        case RTI_CDR_TK_LONGLONG:return "longlong";
        case RTI_CDR_TK_ULONGLONG: return "unsigned long long";
        case RTI_CDR_TK_LONGDOUBLE: return "long double";
        case RTI_CDR_TK_WCHAR:  return "wchar";
        case RTI_CDR_TK_WSTRING:return "wstring";
        case RTI_CDR_TK_STRING: return "string";
        case RTI_CDR_TK_SEQUENCE: return "sequence";
        case RTI_CDR_TK_ARRAY: return "array";
        case RTI_CDR_TK_ALIAS: return "alias";
        case RTI_CDR_TK_VALUE: return "valuetype";

        case RTI_CDR_TK_NULL:
        default:
            return "<unknown type>";
    }
}

/* ------------------------------------------------------------------------- */
/* Insert in the protocol tree the next bytes interpreted as typecode info
 * Returns the number of bytes parsed
 */
static gint rtps_util_add_typecode(proto_tree *tree,
                        tvbuff_t * tvb,
                        gint       offset,
                        int        little_endian,
                        int        indent_level,
                        int        is_pointer,
                        guint16    bitfield,
                        int        is_key,
                        const gint offset_begin,
                        char     * name,
                        int        seq_max_len, /* 0 = not a sequence field (-1 = unbounded seq) */
                        guint32 *  arr_dimension, /* if !NULL: array of 10 int */
                        int        ndds_40_hack) {
  const gint original_offset = offset;
  guint32 tk_id;
  guint16 tk_size;
  unsigned int i;
  char    indent_string[40];
  gint    retVal;
  char    type_name[40];

    /* Structure of the typecode data:
     *  Offset   | Size  | Field                        | Notes
     * ----------|-------|------------------------------|---------------------
     *       ?   |    ?  | pad?                         |
     *       0   |    4  | RTI_CDR_TK_XXXXX             | 4 bytes aligned
     *       4   |    2  | length the struct            |
     */

  /* Calc indent string */
  memset(indent_string, ' ', 40);
  indent_string[indent_level*2] = '\0';

  /* Gets TK ID */
  LONG_ALIGN(offset);
  tk_id = NEXT_guint32(tvb, offset, little_endian);
  offset += 4;

  /* Gets TK size */
  tk_size = NEXT_guint16(tvb, offset, little_endian);
  offset += 2;

  retVal = tk_size + 6; /* 6 = 4 (typecode ID) + 2 (size) */

  /* The first bit of typecode is set to 1, clear it */
  tk_id &= 0x7fffffff;

  /* HACK: NDDS 4.0 and NDDS 4.1 has different typecode ID list.
   * The ID listed in the RTI_CDR_TK_XXXXX are the one from NDDS 4.1
   * In order to correctly dissect NDDS 4.0 packets containing typecode
   * information, we check if the ID of the element at level zero is a
   * struct or union. If not, it means we are dissecting a ndds 4.0 packet
   * (and we can decrement the ID to match the correct values).
   */
  if (indent_level == 0) {
    if (tk_id == RTI_CDR_TK_OCTET) {
      ndds_40_hack = 1;
    }
  }
  if (ndds_40_hack) {
    ++tk_id;
  }

  g_strlcpy(type_name, rtps_util_typecode_id_to_string(tk_id), 40);

    /* Structure of the typecode data:
     *
     * <type_code_header> ::=
     *          <kind>
     *          <type_code_length>
     *
     * <kind> ::= long (0=TK_NULL, 1=TK_SHORT...)
     * <type_code_length> ::= unsugned short
     *
     */
  switch(tk_id) {

    /* Structure of the typecode data:
     *
     * <union_type_code> ::=
     *          <type_code_header>
     *          <name>
     *          <default_index>
     *          <discriminator_type_code>
     *          <member_count>
     *          <union_member>+
     * <union_member> ::= <member_length><name><union_member_detail>
     * <member_length> ::= unsigned short
     * <name>   ::= <string>
     * <string> ::= <length>char+<eol>
     * <length> ::= unsigned long
     * <eol>    ::= (char)0
     *
     * <union_member_detail> ::= <is_pointer>
     *          <labels_count>
     *          <label>+
     *          <type_code>
     * <labels_count> ::= unsigned long
     * <label> ::= long
     *
     */
    case RTI_CDR_TK_UNION: {
        guint32 struct_name_len;
        gint8 * struct_name;
        const char * discriminator_name = "<unknown>";    /* for unions */
        char *       discriminator_enum_name = NULL;      /* for unions with enum discriminator */
        /*guint32 defaultIdx;*/ /* Currently is ignored */
        guint32 disc_id;    /* Used temporarily to populate 'discriminator_name' */
        guint16 disc_size;  /* Currently is ignored */
        guint32 disc_offset_begin;
        guint32 num_members;
        guint16 member_length;
        guint32 member_name_len;
        guint8 *member_name = NULL;
        guint8  member_is_pointer;
        guint32 next_offset;
        guint32 field_offset_begin;
        guint32 member_label_count;
        gint32  member_label;
        guint32 discriminator_enum_name_length;
        guint   j;

        /* - - - - - - -      Union name      - - - - - - - */
        /* Pad-align */
        LONG_ALIGN(offset);

        /* Get structure name length */
        struct_name_len = NEXT_guint32(tvb, offset, little_endian);
        offset += 4;
        struct_name = tvb_get_ephemeral_string(tvb, offset, struct_name_len);
        offset += struct_name_len;

        /* - - - - - - -      Default index      - - - - - - - */
        LONG_ALIGN(offset);
        /*defaultIdx = NEXT_guint32(tvb, offset, little_endian);*/
        offset += 4;

        /* - - - - - - -      Discriminator type code     - - - - - - - */
        /* We don't recursively dissect everything, instead we just read the type */
        disc_id = NEXT_guint32(tvb, offset, little_endian);
        offset += 4;

        disc_size = NEXT_guint16(tvb, offset, little_endian);
        offset += 2;
        disc_offset_begin = offset;
        disc_id &= 0x7fffffff;
        discriminator_name = rtps_util_typecode_id_to_string(disc_id);
        if (disc_id == RTI_CDR_TK_ENUM) {
            /* Enums has also a name that we should print */
            LONG_ALIGN(offset);
            discriminator_enum_name_length = NEXT_guint32(tvb, offset, little_endian);
            discriminator_enum_name = tvb_get_ephemeral_string(tvb, offset+4, discriminator_enum_name_length);
        }
        offset = disc_offset_begin + disc_size;
/*
            field_offset_begin = offset;
            offset += rtps_util_add_typecode(
                          tree,
                          tvb,         next_offset = offset;

                          offset,
                          little_endian,
                          indent_level+1,
                          0,
                          0,
                          0,
                          field_offset_begin,
                          member_name,
                          0,
                          NULL,
                          ndds_40_hack);
*/


        /* Add the entry of the union in the tree */
        proto_tree_add_text(tree,
                    tvb,
                    original_offset,
                    retVal,
                    "%sunion %s (%s%s%s) {",
                    indent_string,
                    struct_name,
                    discriminator_name,
                    (discriminator_enum_name ? " " : ""),
                    (discriminator_enum_name ? discriminator_enum_name : ""));

        if (seq_max_len != 0) {
          /* We're dissecting a sequence of struct, bypass the seq definition */
          g_snprintf(type_name, 40, "%s", struct_name);
          break;
        }

        /* - - - - - - -      Number of members     - - - - - - - */
        LONG_ALIGN(offset);
        num_members = NEXT_guint32(tvb, offset, little_endian);
        offset += 4;

        /* - - - - - - -      <union_member>+     - - - - - - - */
        next_offset = offset;

        for (i = 0; i < num_members; ++i) {
          /* Safety: this theoretically should be the same already */
          field_offset_begin = offset = next_offset;

          SHORT_ALIGN(offset);

          /* member's length */
          member_length = NEXT_guint16(tvb, offset, little_endian);
          offset += 2;
          next_offset = offset + member_length;

          /* Name length */
          LONG_ALIGN(offset);
          member_name_len = NEXT_guint32(tvb, offset, little_endian);
          offset += 4;

          /* Name */
          member_name = tvb_get_ephemeral_string(tvb, offset, member_name_len);
          offset += member_name_len;

          /* is Pointer ? */
          member_is_pointer = tvb_get_guint8(tvb, offset);
          offset++;

          /* Label count */
          LONG_ALIGN(offset);
          member_label_count = NEXT_guint32(tvb, offset, little_endian);
          offset += 4;

          for (j = 0; j < member_label_count; ++j) {
            /* Label count */
            LONG_ALIGN(offset);
            member_label = NEXT_guint32(tvb, offset, little_endian);
            offset += 4;

            /* Add the entry of the union in the tree */
            proto_tree_add_text(tree,
                    tvb,
                    field_offset_begin,
                    retVal,
                    "%s  case %d:",
                    indent_string,
                    member_label);
          }

          offset += rtps_util_add_typecode(
                    tree,
                    tvb,
                    offset,
                    little_endian,
                    indent_level+2,
                    member_is_pointer,
                    0,
                    0,
                    field_offset_begin,
                    member_name,
                    0,
                    NULL,
                    ndds_40_hack);
        }
        /* Finally prints the name of the struct (if provided) */
        g_strlcpy(type_name, "}", 40);
        break;

    } /* end of case UNION */


    case RTI_CDR_TK_ENUM:
    case RTI_CDR_TK_STRUCT: {
    /* Structure of the typecode data:
     *
     * <union_type_code> ::=
     *          <type_code_header>
     *          <name>
     *          <default_index>
     *          <discriminator_type_code>
     *          <member_count>
     *          <member>+
     *
     * <struct_type_code> ::=
     *          <type_code_header>
     *          <name>
     *          <member_count>
     *          <member>+
     *
     * <name>   ::= <string>
     * <string> ::= <length>char+<eol>
     * <length> ::= unsigned long
     * <eol>    ::= (char)0
     * <member_count> ::= unsigned long
     *
     * STRUCT / UNION:
     *     Foreach member {
     *          - A2: 2: member length
     *          - A4: 4: member name length
     *          -     n: member name
     *          -     1: isPointer?
     *          - A2  2: bitfield bits (-1=none)
     *          -     1: isKey?
     *          - A4  4: Typecode ID
     *          - A2  2: length
     * }
     *
     * ENUM:
     *     Foreach member {
     *          - A2: 2: member length
     *          - A4: 4: member name length
     *          -     n: member name
     *          - A4: 4: ordinal number
     *
     * -> ----------------------------------------------------- <-
     * -> The alignment pad bytes belong to the FOLLOWING field <-
     * ->    A4 = 4 bytes alignment, A2 = 2 bytes alignment     <-
     * -> ----------------------------------------------------- <-
     */
        guint32 struct_name_len;
        gint8 * struct_name;
        guint32 num_members;
        guint16 member_length;
        guint8  member_is_pointer;
        guint16 member_bitfield;
        guint8  member_is_key;
        guint32 member_name_len;
        guint8 *member_name = NULL;
        guint32 next_offset;
        guint32 field_offset_begin;
        guint32 ordinal_number;
        const char * typecode_name;

        /* Pad-align */
        LONG_ALIGN(offset);

        /* Get structure name length */
        struct_name_len = NEXT_guint32(tvb, offset, little_endian);
        offset += 4;

        /* struct name */
        struct_name = tvb_get_ephemeral_string(tvb, offset, struct_name_len);
        offset += struct_name_len;


        if (tk_id == RTI_CDR_TK_ENUM) {
            typecode_name = "enum";
        } else if (tk_id == RTI_CDR_TK_VALUE_PARARM) {
            /*guint16 type_modifier;*/
            /*guint32 baseTypeCodeKind;*/
            guint32 baseTypeCodeLength;
            /* Need to read the type modifier and the base type code */
            typecode_name = "<sparse type>";
            SHORT_ALIGN(offset);
            /*type_modifier = NEXT_guint16(tvb, offset, little_endian);*/
            offset += 2;
            LONG_ALIGN(offset);
            /*baseTypeCodeKind = NEXT_guint32(tvb, offset, little_endian);*/
            offset += 4;
            baseTypeCodeLength = NEXT_guint32(tvb, offset, little_endian);
            offset += 4;
            offset += baseTypeCodeLength;
        } else {
            typecode_name = "struct";
        }

        if (seq_max_len != 0) {
          /* We're dissecting a sequence of struct, bypass the seq definition */
          g_snprintf(type_name, 40, "%s", struct_name);
          break;
        }
        /* Prints the typecode header */
        proto_tree_add_text(tree,
                    tvb,
                    original_offset,
                    retVal,
                    "%s%s %s {",
                    indent_string,
                    typecode_name,
                    struct_name);

        /* PAD align */
        LONG_ALIGN(offset);

        /* number of members */
        num_members = NEXT_guint32(tvb, offset, little_endian);
        offset += 4;

        next_offset = offset;
        for (i = 0; i < num_members; ++i) {
          /* Safety: this theoretically should be the same already */
          field_offset_begin = offset = next_offset;

          SHORT_ALIGN(offset);

          /* member's length */
          member_length = NEXT_guint16(tvb, offset, little_endian);
          offset += 2;
          next_offset = offset + member_length;

          /* Name length */
          LONG_ALIGN(offset);
          member_name_len = NEXT_guint32(tvb, offset, little_endian);
          offset += 4;

          /* Name */
          member_name = tvb_get_ephemeral_string(tvb, offset, member_name_len);
          offset += member_name_len;

          if (tk_id == RTI_CDR_TK_ENUM) {
            /* ordinal number */
            LONG_ALIGN(offset);
            ordinal_number = NEXT_guint32(tvb, offset, little_endian);
            offset += 4;

            proto_tree_add_text(tree,
                  tvb,
                  field_offset_begin,
                  (offset-field_offset_begin),
                  "%s  %s = %d;",
                  indent_string,
                  member_name,
                  ordinal_number);
          } else {
            /* Structs */

            /* is Pointer ? */
            member_is_pointer = tvb_get_guint8(tvb, offset);
            offset++;

            /* Bitfield */
            SHORT_ALIGN(offset);
            member_bitfield = NEXT_guint16(tvb, offset, little_endian);
            offset += 2; /* pad will be added by typecode dissector */

            /* is Key ? */
            member_is_key = tvb_get_guint8(tvb, offset);
            offset++;

            offset += rtps_util_add_typecode(
                          tree,
                          tvb,
                          offset,
                          little_endian,
                          indent_level+1,
                          member_is_pointer,
                          member_bitfield,
                          member_is_key,
                          field_offset_begin,
                          member_name,
                          0,
                          NULL,
                          ndds_40_hack);
          }
        }
        /* Finally prints the name of the struct (if provided) */
        g_strlcpy(type_name, "}", 40);
        break;
      }

    case RTI_CDR_TK_WSTRING:
    case RTI_CDR_TK_STRING: {
    /* Structure of the typecode data:
     *  Offset   | Size  | Field                        | Notes
     * ----------|-------|------------------------------|---------------------
     *     6     |   2   | pad                          |
     *     8     |   4   | String length                | 4-bytes aligned
     */
        guint32 string_length;

        LONG_ALIGN(offset);
        string_length = NEXT_guint32(tvb, offset, little_endian);
        offset += 4;
        g_snprintf(type_name, 40, "%s<%d>",
                (tk_id == RTI_CDR_TK_STRING) ? "string" : "wstring",
                string_length);
        break;
    }

    case RTI_CDR_TK_SEQUENCE: {
    /* Structure of the typecode data:
     *
     * - A4: 4: Sequence max length
     * - the sequence typecode
     */
        guint32 seq_max_len2;
        LONG_ALIGN(offset);
        seq_max_len2 = NEXT_guint32(tvb, offset, little_endian);
        offset += 4;

        /* Recursive decode seq typecode */
        offset += rtps_util_add_typecode(
                          tree,
                          tvb,
                          offset,
                          little_endian,
                          indent_level,
                          is_pointer,
                          bitfield,
                          is_key,
                          offset_begin,
                          name,
                          seq_max_len2,
                          NULL,
                          ndds_40_hack);
        /* Differently from the other typecodes, the line has been already printed */
        return retVal;
    }

    case RTI_CDR_TK_ARRAY: {
    /* Structure of the typecode data:
     *
     * - A4: 4: number of dimensions
     * - A4: 4: dim1
     * - <A4: 4: dim2>
     * - ...
     * - the array typecode
     */
        guint32 size[MAX_ARRAY_DIMENSION]; /* Max dimensions */
        guint32 dim_max;

        LONG_ALIGN(offset);
        dim_max = NEXT_guint32(tvb, offset, little_endian);
        offset += 4;

        for (i = 0; i < MAX_ARRAY_DIMENSION; ++i) size[i] = 0;
        for (i = 0; i < dim_max; ++i) {
          size[i] = NEXT_guint32(tvb, offset, little_endian);
          offset += 4;
        }

        /* Recursive decode seq typecode */
        offset += rtps_util_add_typecode(
                          tree,
                          tvb,
                          offset,
                          little_endian,
                          indent_level,
                          is_pointer,
                          bitfield,
                          is_key,
                          offset_begin,
                          name,
                          0,
                          size,
                          ndds_40_hack);
        /* Differently from the other typecodes, the line has been already printed */
        return retVal;
    }

    case RTI_CDR_TK_ALIAS: {
    /* Structure of the typecode data:
     *
     * - A4: 4: alias name size
     * - A4: 4: alias name
     * - A4: 4: the alias typecode
     */
        guint32 alias_name_length;
        guint8 *alias_name;

        LONG_ALIGN(offset);
        alias_name_length = NEXT_guint32(tvb, offset, little_endian);
        offset += 4;
        alias_name = tvb_get_ephemeral_string(tvb, offset, alias_name_length);
        offset += alias_name_length;
        g_strlcpy(type_name, alias_name, 40);
        break;
    }


    /*
     * VALUETYPES:
     * - A4: 4: name length
     * -     n: name
     * - A2: type modifier
     * - A4: base type code
     * - A4: number of members
     * Foreach member: (it's just like a struct)
     *
     */
    case RTI_CDR_TK_VALUE_PARARM:
    case RTI_CDR_TK_VALUE: {
        /* Not fully dissected for now */
        /* Pad-align */
        guint32 value_name_len;
        gint8 * value_name;
        const char * type_id_name = "valuetype";
        LONG_ALIGN(offset);

        /* Get structure name length */
        value_name_len = NEXT_guint32(tvb, offset, little_endian);
        offset += 4;

        /* value name */
        value_name = tvb_get_ephemeral_string(tvb, offset, value_name_len);
        offset += value_name_len;

        if (tk_id == RTI_CDR_TK_VALUE_PARARM) {
            type_id_name = "valueparam";
        }
        g_snprintf(type_name, 40, "%s '%s'", type_id_name, value_name);
        break;
    }
  } /* switch(tk_id) */

  /* Sequence print */
  if (seq_max_len != 0) {
    proto_tree_add_text(tree,
                  tvb,
                  offset_begin,
                  (offset-offset_begin),
                  "%ssequence<%s, %d> %s%s;%s",
                  indent_string,
                  type_name,
                  seq_max_len,
                  is_pointer ? "*" : "",
                  name ? name : "",
                  is_key ? KEY_COMMENT : "");
    return retVal;
  }

  /* Array print */
  if (arr_dimension != NULL) {
    /* Printing an array */
    emem_strbuf_t *dim_str = ep_strbuf_new_label("");
    for (i = 0; i < MAX_ARRAY_DIMENSION; ++i) {
      if (arr_dimension[i] != 0) {
        ep_strbuf_append_printf(dim_str, "[%d]", arr_dimension[i]);
      } else {
        break;
      }
    }
    proto_tree_add_text(tree,
                  tvb,
                  offset_begin,
                  (offset-offset_begin),
                  "%s%s %s%s;%s",
                  indent_string,
                  type_name,
                  name ? name : "",
                  dim_str->str,
                  is_key ? KEY_COMMENT : "");
    return retVal;
  }

  /* Bitfield print */
  if (bitfield != 0xffff && name != NULL && is_pointer == 0) {
    proto_tree_add_text(tree,
                  tvb,
                  offset_begin,
                  (offset-offset_begin),
                  "%s%s %s:%d;%s",
                  indent_string,
                  type_name,
                  name ? name : "",
                  bitfield,
                  is_key ? KEY_COMMENT : "");
    return retVal;
  }

  /* Everything else */
  proto_tree_add_text(tree,
                  tvb,
                  offset_begin,
                  (offset-offset_begin),
                  "%s%s%s%s%s;%s",
                  indent_string,
                  type_name,
                  name ? " " : "",
                  is_pointer ? "*" : "",
                  name ? name : "",
                  is_key ? KEY_COMMENT : "");
  return retVal;
}


/* ------------------------------------------------------------------------- */
/* Insert in the protocol tree the next bytes interpreted as Sequence of
 * Octets.
 * The formatted buffer is: [ 0x01, 0x02, 0x03, 0x04, ...]
 * The maximum number of elements displayed is 10, after that a '...' is
 * inserted.
 */
static void rtps_util_add_seq_octets(proto_tree *tree,
                        tvbuff_t * tvb,
                        gint       offset,
                        int        little_endian,
                        int        param_length,
                        int        hf_id,
                        guint8 *   buffer,
                        gint       buffer_size) {
  gint idx = 0;
  guint32 seq_length;
  guint32 i;
  gint original_offset = offset;
  guint32 original_seq_length;


  original_seq_length = seq_length = NEXT_guint32(tvb, offset, little_endian);

  offset += 4;
  if (param_length < 4 + (int)seq_length) {
    g_strlcpy(buffer, "RTPS PROTOCOL ERROR: parameter value too small", buffer_size);
    if (tree) {
      proto_tree_add_text(tree,
                        tvb,
                        offset,
                        param_length,
                        "%s",
                        buffer);
    }
    return ;
  }

  /* Limit the number of octets displayed to MAX_SEQ_OCTETS_PRINTED */
  if (seq_length > MAX_SEQ_OCTETS_PRINTED) {
    seq_length = MAX_SEQ_OCTETS_PRINTED;
  }
  for (i = 0; i < seq_length; ++i) {
    idx += g_snprintf(&buffer[idx],
                        buffer_size - idx - 1,
                        "%02x",
                        tvb_get_guint8(tvb, offset++));
    if (idx >= buffer_size) {
        break;
    }
  }
  if (seq_length != original_seq_length) {
    /* seq_length was reduced, add '...' */
    g_strlcat(buffer, "...", buffer_size);
  }

  if (tree) {
    proto_tree_add_text(tree,
                        tvb,
                        original_offset,
                        4,
                        "sequenceSize: %d octets",
                        original_seq_length);
    proto_tree_add_item(tree,
                        hf_id,
                        tvb,
                        original_offset+4,
                        original_seq_length,
                        little_endian);

  }
}




/* ------------------------------------------------------------------------- */
/* Insert in the protocol tree the next bytes interpreted as a Bitmap
 * struct {
 *     SequenceNumber_t    bitmapBase;
 *     sequence<long, 8>   bitmap;
 * } SequenceNumberSet;
 *
 * Returns the new offset after reading the bitmap.
 */
static int rtps_util_add_bitmap(proto_tree *tree,
                        tvbuff_t * tvb,
                        gint       offset,
                        int        little_endian,
                        const char *label _U_) {
  guint64 seq_base;
  gint32 num_bits;
  guint32 data;
  char temp_buff[MAX_BITMAP_SIZE];
  int i, j, idx;
  proto_item * ti;
  proto_tree * bitmap_tree;
  const gint original_offset = offset;
  guint32 datamask;

  /* Bitmap base sequence number */
  seq_base = rtps_util_add_seq_number(NULL,
                        tvb,
                        offset,
                        little_endian,
                        NULL);
  offset += 8;

  /* Reads the bitmap size */
  num_bits = NEXT_guint32(tvb, offset, little_endian);

  offset += 4;

  /* Reads the bits (and format the print buffer) */
  idx = 0;
  temp_buff[0] = '\0';
  for (i = 0; i < num_bits; i += 32) {
    data = NEXT_guint32(tvb, offset, little_endian);
    offset += 4;
    for (j = 0; j < 32; ++j) {
      datamask = (1 << (31-j));
      temp_buff[idx] = ((data & datamask) == datamask) ? '1':'0';
      ++idx;
      if (idx >= num_bits) {
        break;
      }
      if (idx >= MAX_BITMAP_SIZE-1) {
        break;
      }
    }
  }
  temp_buff[idx] = '\0';

  /* removes all the ending '0' */
  for (i = (int)strlen(temp_buff) - 1; (i>0 && temp_buff[i] == '0'); --i) {
      temp_buff[i] = '\0';
  }

  if (tree) {
    ti = proto_tree_add_text(tree,
                          tvb,
                          original_offset,
                          offset-original_offset,
                          "%s: %" G_GINT64_MODIFIER "u/%d:%s",
                          label,
                          seq_base,
                          num_bits,
                          temp_buff);
    bitmap_tree = proto_item_add_subtree(ti, ett_rtps_bitmap);
    proto_tree_add_text(bitmap_tree,
                          tvb,
                          original_offset,
                          8,
                          "bitmapBase: %" G_GINT64_MODIFIER "u",
                          seq_base);
    proto_tree_add_text(bitmap_tree,
                          tvb,
                          original_offset + 8,
                          4,
                          "numBits: %u",
                          num_bits);
    if (temp_buff[0] != '\0') {
      proto_tree_add_text(bitmap_tree,
                          tvb,
                          original_offset + 12,
                          offset - original_offset - 12,
                          "bitmap: %s",
                          temp_buff);
    }
  }
  return offset;
}

/* ------------------------------------------------------------------------- */
/* Insert in the protocol tree the next bytes interpreted as a FragmentNumberSet
 * typedef unsigned long FragmentNumber_t;
 * struct {
 *     FragmentNumber_t              bitmapBase;
 *     sequence<FragmentNumber_t>    bitmap;
 * } FragmentNumberSet;
 *
 * Returns the new offset after reading the bitmap.
 */
static int rtps_util_add_fragment_number_set(proto_tree *tree,
                        tvbuff_t * tvb,
                        gint       offset,
                        int        little_endian,
                        const char *label _U_,
                        gint       section_size) {
  guint64 base;
  gint32 num_bits;
  guint32 data;
  char temp_buff[MAX_BITMAP_SIZE];
  int i, j, idx;
  proto_item * ti;
  proto_tree * bitmap_tree;
  const gint original_offset = offset;
  guint32 datamask;
  gint expected_size;
  gint base_size;

  /* RTI DDS 4.2d was sending the FragmentNumber_t as a 64-bit long integer
   * instead of 32-bit long.
   * Attempt to decode this section as 32-bit, then check if the size of the
   * message match what is here. If not re-decode it as 64-bit.
   */
  num_bits = NEXT_guint32(tvb, offset+4, little_endian);
  expected_size = (((num_bits / 8) + 3) / 4) * 4 + 8;
  if (expected_size == section_size) {
    base = (guint64)NEXT_guint32(tvb, offset, little_endian);
    base_size = 4;
    offset += 8;
  } else {
    /* Attempt to use 64-bit for base */
    num_bits = NEXT_guint32(tvb, offset+8, little_endian);
    /* num_bits/8 must be aligned to the 4-byte word */
    expected_size = (((num_bits / 8) + 3) / 4) * 4 + 12;
    if (expected_size == section_size) {
      guint64 hi = (guint64)NEXT_guint32(tvb, offset, little_endian);
      guint64 lo = (guint64)NEXT_guint32(tvb, offset+4, little_endian);
      base = (hi << 32) | lo;
      base_size = 8;
      offset += 12;
    } else {
      /* size don't match, packet error */
      if (tree) {
        proto_tree_add_text(tree,
                        tvb,
                        original_offset,
                        section_size,
                        "Packet malformed: illegal size for fragment number set");
      }
      return -1;
    }
  }

  /* Reads the bits (and format the print buffer) */
  idx = 0;
  temp_buff[0] = '\0';
  for (i = 0; i < num_bits; i += 32) {
    data = NEXT_guint32(tvb, offset, little_endian);
    offset += 4;
    for (j = 0; j < 32; ++j) {
      datamask = (1 << (31-j));
      temp_buff[idx] = ((data & datamask) != 0) ? '1':'0';
      ++idx;
      if (idx > num_bits) {
        break;
      }
      if (idx >= MAX_BITMAP_SIZE-1) {
        break;
      }
    }
  }
  temp_buff[idx] = '\0';

  /* removes all (but the last one) characters '0' */
  for (i = (int)strlen(temp_buff) - 1; (i>0 && temp_buff[i] == '0'); --i) {
      temp_buff[i] = '\0';
  }
  if (tree) {
    ti = proto_tree_add_text(tree,
                        tvb,
                        original_offset,
                        offset-original_offset,
                        "%s: %" G_GINT64_MODIFIER "u/%d:%s",
                        label,
                        base,
                        num_bits,
                        temp_buff);
    bitmap_tree = proto_item_add_subtree(ti, ett_rtps_bitmap);
    proto_tree_add_text(bitmap_tree,
                        tvb,
                        original_offset,
                        base_size,
                        "bitmapBase: %" G_GINT64_MODIFIER "u",
                        base);
    proto_tree_add_text(bitmap_tree,
                        tvb,
                        original_offset + base_size,
                        4,
                        "numBits: %u",
                        num_bits);
    if (temp_buff[0] != '\0') {
      proto_tree_add_text(bitmap_tree,
                        tvb,
                        original_offset + base_size + 4,
                        offset - original_offset - base_size - 4,
                        "bitmap: %s",
                        temp_buff);
    }
  }
  return offset;
}


/* ------------------------------------------------------------------------- */
/* Decode the submessage flags (8 bit version)
 */
static void rtps_util_decode_flags(proto_tree * tree,
                        tvbuff_t *tvb,
                        gint      offset,
                        guint8 flags,
                        const struct Flag_definition * flag_def) {

  proto_item * ti;
  proto_tree * flags_tree;
  int i, j;
  char flags_str[MAX_FLAG_SIZE];
  if (tree == NULL) {
    return;
  }

  flags_str[0] = '\0';
  for (i = 0; i < 8; ++i) {
    g_snprintf(flags_str + (2 * i), MAX_FLAG_SIZE - (2 * i), "%c ",
                ((flags & (1<<(7-i))) ? flag_def[i].letter : RESERVEDFLAG_CHAR));
  }

  ti = proto_tree_add_uint_format(tree,
                        hf_rtps_sm_flags,
                        tvb,
                        offset,
                        1,
                        flags,
                        "Flags: 0x%02x (%s)",
                        flags,
                        flags_str);

  flags_tree = proto_item_add_subtree(ti,
                        ett_rtps_flags);

  for (i = 0; i < 8; ++i) {
    int is_set = (flags & (1 << (7-i)));

    for (j = 0; j < 8; ++j) {
      flags_str[j] = (i == j) ? (is_set ? '1' : '0') : '.';
    }
    flags_str[8] = '\0';

    proto_tree_add_text(flags_tree,
                        tvb,
                        offset,
                        1,
                        "%s = %s: %s",
                        flags_str,
                        flag_def[i].description,
                        is_set ? "Set" : "Not set");
  }

}

/* ------------------------------------------------------------------------- */
/* Decode the submessage flags (16 bit version)
 */
static void rtps_util_decode_flags_16bit(proto_tree * tree,
                        tvbuff_t *tvb,
                        gint   offset,
                        guint16 flags,
                        const struct Flag_definition * flag_def) {

  proto_item * ti;
  proto_tree * flags_tree;
  int i, j;
  char flags_str[MAX_FLAG_SIZE];
  if (tree == NULL) {
    return;
  }

  flags_str[0] = '\0';
  for (i = 0; i < 16; ++i) {
    g_snprintf(flags_str + (2 * i), MAX_FLAG_SIZE - (2 * i), "%c ",
                ((flags & (1<<(15-i))) ? flag_def[i].letter : RESERVEDFLAG_CHAR));
  }

  ti = proto_tree_add_uint_format(tree,
                        hf_rtps_sm_flags,
                        tvb,
                        offset,
                        2,
                        flags,
                        "Flags: 0x%04x (%s)",
                        flags,
                        flags_str);

  flags_tree = proto_item_add_subtree(ti,
                        ett_rtps_flags);

  for (i = 0; i < 16; ++i) {
    int is_set = (flags & (1 << (15-i)));

    for (j = 0; j < 16; ++j) {
      flags_str[j] = (i == j) ? (is_set ? '1' : '0') : '.';
    }
    flags_str[16] = '\0';

    proto_tree_add_text(flags_tree,
                        tvb,
                        offset,
                        2,
                        "%s = %s: %s",
                        flags_str,
                        flag_def[i].description,
                        is_set ? "Set" : "Not set");
  }
}



/* *********************************************************************** */
/* * Serialized data dissector                                           * */
/* *********************************************************************** */
/* Note: the encapsulation header is ALWAYS big endian, then the encapsulation
 * type specified the type of endianess of the payload.
 */
static void dissect_serialized_data(proto_tree *tree,
                        tvbuff_t *tvb,
                        gint offset,
                        int  size,
                        const char * label,
                        guint16 vendor_id) {
  proto_item * ti;
  proto_tree * rtps_parameter_sequence_tree;
  guint16 encapsulation_id;
  guint16 encapsulation_len;
  int encapsulation_little_endian = 0;
  if (tree == NULL) {
    return;
  }

  /* Creates the sub-tree */
  ti = proto_tree_add_text(tree,
                        tvb,
                        offset,
                        -1,
                        "%s:", label);
  rtps_parameter_sequence_tree = proto_item_add_subtree(ti,
                        ett_rtps_serialized_data);


  /* Encapsulation ID */
  encapsulation_id =  NEXT_guint16(tvb, offset, 0);   /* Always big endian */

  proto_tree_add_text(rtps_parameter_sequence_tree,
                        tvb,
                        offset,
                        2,
                        "encapsulation kind: %s",
                        val_to_str(encapsulation_id, encapsulation_id_vals, "unknown (%02x)"));
  offset += 2;

  /* Sets the correct values for encapsulation_le */
  if (encapsulation_id == ENCAPSULATION_CDR_LE ||
      encapsulation_id == ENCAPSULATION_PL_CDR_LE) {
    encapsulation_little_endian = 1;
  }

  /* Encapsulation length (or option) */
  encapsulation_len =  NEXT_guint16(tvb, offset, 0);    /* Always big endian */
  proto_tree_add_text(rtps_parameter_sequence_tree,
                        tvb,
                        offset,
                        2,
                        "encapsulation options: %04x",
                        encapsulation_len);
  offset += 2;

  /* The payload */
  size -= 4;
  switch (encapsulation_id) {
    case ENCAPSULATION_CDR_LE:
    case ENCAPSULATION_CDR_BE:
          proto_tree_add_item(rtps_parameter_sequence_tree,
                        hf_rtps_issue_data,
                        tvb,
                        offset,
                        size,
                        encapsulation_little_endian);
          break;

    case ENCAPSULATION_PL_CDR_LE:
    case ENCAPSULATION_PL_CDR_BE:
          dissect_parameter_sequence(rtps_parameter_sequence_tree,
                        tvb,
                        offset,
                        encapsulation_little_endian,
                        size,
                        label, NULL, vendor_id);
          break;

    default:
          proto_tree_add_text(rtps_parameter_sequence_tree,
                        tvb,
                        offset,
                        size,
                        "%s",
                        label);
  }
}


/* ***********************************************************************
 * The dissector for octet seq (serialized data)
 * For a sequence of octets, the first word is always the sequence length
 * followed by all the raw bytes.
 */
static void dissect_octet_seq(proto_tree *tree,
                        tvbuff_t *tvb,
                        gint offset,
                        const char * label) {
  proto_item * ti;
  proto_tree * rtps_parameter_sequence_tree;
  guint32 length;
  if (tree == NULL) {
    return;
  }

  /* Creates the sub-tree */
  ti = proto_tree_add_text(tree,
                        tvb,
                        offset,
                        -1,
                        "%s:", label);
  rtps_parameter_sequence_tree = proto_item_add_subtree(ti,
                        ett_rtps_serialized_data);


  /* Length */
  length =  NEXT_guint32(tvb, offset, 0);   /* Always big endian */

  proto_tree_add_text(rtps_parameter_sequence_tree,
                        tvb,
                        offset,
                        4,
                        "Sequence length: %d", length);
  offset += 4;

  /* The payload */
  proto_tree_add_item(rtps_parameter_sequence_tree,
                        hf_rtps_issue_data,
                        tvb,
                        offset,
                        length,
                        0);
}



/* *********************************************************************** */
/* * Parameter Sequence dissector                                        * */
/* *********************************************************************** */
/*
 * It returns the new offset representing the point where the parameter
 * sequence terminates.
 * In case of protocol error, it returns 0 (cannot determine the end of
 * the sequence, the caller should be responsible to find the end of the
 * section if possible or pass the error back and abort dissecting the
 * current packet).
 * If no error occurred, the returned value is ALWAYS > than the offset passed.
 *
 * Note: even if tree==NULL, we still have to go through the PID because
 *       since RTPS 2.1, the status info is now stored in a PID (and the
 *       status info is required to format the INFO column).
 */
#define ENSURE_LENGTH(size)                                             \
        if (param_length < size) {                                      \
          proto_tree_add_text(rtps_parameter_tree,                      \
                        tvb, offset, param_length,                      \
                        "RTPS PROTOCOL ERROR: parameter value too small"\
                        " (must be at least %d octets)", size);         \
          break;                                                        \
        }

static gint dissect_parameter_sequence(proto_tree *tree,
                        tvbuff_t *tvb,
                        gint offset,
                        int  little_endian,
                        int  size,
                        const char * label,
                        guint32 *pStatusInfo,
                        guint16 vendor_id) {
  proto_item * ti = NULL;
  proto_tree * rtps_parameter_sequence_tree = NULL;
  proto_tree * rtps_parameter_tree = NULL;
  guint16      parameter, param_length;
  guint8       buffer[MAX_PARAM_SIZE];
  gint         original_offset = offset;

  buffer[0] = '\0';
  if (tree) {
    ti = proto_tree_add_text(tree,
                        tvb,
                        offset,
                        -1,
                        "%s:", label);
    rtps_parameter_sequence_tree = proto_item_add_subtree(ti,
                        ett_rtps_parameter_sequence);
  }

  /* Loop through all the parameters defined until PID_SENTINEL is found */
  for (;;) {
    size -= offset - original_offset;
    if (size < 4) {
      proto_tree_add_text(tree,
                        tvb,
                        offset,
                        1,
                        "RTPS PROTOCOL ERROR: not enough bytes to read "
                                                " the next parameter");
      return 0;
    }
    original_offset = offset;

    /* Reads parameter and create the sub tree. At this point we don't know
     * the final string that will identify the node or its length. It will
     * be set later...
     */
    parameter = NEXT_guint16(tvb, offset, little_endian);
    if (tree) {
      ti = proto_tree_add_text(rtps_parameter_sequence_tree,
                        tvb,
                        offset,
                        -1,
                        "%s",
                        val_to_str(parameter, parameter_id_vals,
                                "Unknown (0x%04x)"));
      rtps_parameter_tree = proto_item_add_subtree(ti, ett_rtps_parameter);
      proto_tree_add_uint_format(rtps_parameter_tree,
                        hf_rtps_parameter_id,
                        tvb,
                        offset,
                        2,
                        parameter,
                        "parameterId: 0x%04x (%s)",
                        parameter,
                        val_to_str(parameter, parameter_id_vals,
                                        "unknown %04x"));
    }
    offset += 2;

    if (parameter == PID_SENTINEL) {
        /* PID_SENTINEL closes the parameter list, (length is ignored) */
        return offset +2;
    }

    /* parameter length */
    param_length = NEXT_guint16(tvb, offset, little_endian);
    if (tree) {
      proto_tree_add_item(rtps_parameter_tree,
                        hf_rtps_parameter_length,
                        tvb,
                        offset,
                        2,
                        little_endian);
    }
    offset += 2;
    /* Make sure we have enough bytes for the param value */
    if (size-4 < param_length)  {
      if (tree) {
        proto_tree_add_text(tree,
                        tvb,
                        offset,
                        1,
                        "RTPS PROTOCOL ERROR: not enough bytes to read"
                                                " the parameter value");
      }
      return 0;
    }

    /* Sets the end of this item (now we know it!) */
    if (tree) {
      proto_item_set_len(ti, param_length+4);
    }

    /* Do a shortcut when tree == NULL. In this case we only care of
     * PID_STATUS_INFO.
     */
    if (tree == NULL) {
      if (parameter == PID_STATUS_INFO) {
        if (pStatusInfo != NULL) {
          *pStatusInfo = NEXT_guint32(tvb, offset, little_endian);
        }
      }
      offset += param_length;
      continue;
    }

    switch(parameter) {

      /* 0...2...........7...............15.............23...............31
       * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       * | PID_STATUS_INFO               |            0x0004             |
       * +---------------+---------------+---------------+---------------+
       * |    long              statusInfo                               |
       * +---------------+---------------+---------------+---------------+
       */
      case PID_STATUS_INFO: {
        guint32 si = 0xffffffff;
        ENSURE_LENGTH(4);
        si = rtps_util_add_long(rtps_parameter_tree,
                        tvb,
                        offset,
                        hf_rtps_param_status_info,
                        FALSE,  /* ALWAYS in network byte order (big endian) */
                        TRUE,   /* Is Hex ? */
                        FALSE,  /* Is Signed ? */
                        NULL,   /* No Label, use the protocol item ID */
                        buffer,
                        MAX_PARAM_SIZE);
        if (pStatusInfo != NULL) {
          *pStatusInfo = si;
        }
        break;
      }

      /* 0...2...........7...............15.............23...............31
       * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       * | PID_DIRECTED_WRITE            |            0x0010             |
       * +---------------+---------------+---------------+---------------+
       * |                                                               |
       * +-                                                             -+
       * |    octet[12] guidPrefix                                       |
       * +-                                                             -+
       * |                                                               |
       * +---------------+---------------+---------------+---------------+
       * |    octet[4]  entityId                                         |
       * +---------------+---------------+---------------+---------------+
       */
      case PID_DIRECTED_WRITE: {
        guint8   guidPart;
        int i;
        ENSURE_LENGTH(16);
        rtps_util_add_guid_prefix(rtps_parameter_tree,
                        tvb,
                        offset,
                        hf_rtps_sm_guid_prefix,
                        hf_rtps_sm_host_id,
                        hf_rtps_sm_app_id,
                        hf_rtps_sm_counter,
                        "guidPrefix",
                        NULL,
                        0);
        rtps_util_add_entity_id(rtps_parameter_tree,
                        tvb,
                        offset+12,
                        hf_rtps_sm_entity_id,
                        hf_rtps_sm_entity_id_key,
                        hf_rtps_sm_entity_id_kind,
                        ett_rtps_entity,
                        "guidSuffix",
                        NULL);
        memset(buffer, 0, MAX_PARAM_SIZE);
        for (i = 0; i < 16; ++i) {
          guidPart = tvb_get_guint8(tvb, offset+i);
          g_snprintf(buffer+strlen(buffer), MAX_PARAM_SIZE-(gulong)strlen(buffer),
                        "%02x", guidPart);
          if (i == 3 || i == 7 || i == 11) g_strlcat(buffer, ":", MAX_PARAM_SIZE);
        }
        break;
      }


      /* 0...2...........7...............15.............23...............31
       * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       * | PID_KEY_HASH                  |             xxxx              |
       * +---------------+---------------+---------------+---------------+
       * |                                                               |
       * +-                                                             -+
       * |    octet[xxxx] guid                                           |
       * +-                                                             -+
       * |                                                               |
       * +---------------+---------------+---------------+---------------+
       * Differently from the other GUID, the KEY_HASH parameter may have
       * variable length in the future.
       * As consequence, no interpretation is performed here (and no check
       * for size).
       */
      case PID_KEY_HASH: {
        guint8   guidPart;
        int i;
        g_strlcat(buffer, "guid: ", MAX_PARAM_SIZE);
        for (i = 0; i < param_length; ++i) {
          guidPart = tvb_get_guint8(tvb, offset+i);
          g_snprintf(buffer+strlen(buffer), MAX_PARAM_SIZE-(gulong)strlen(buffer),
                        "%02x", guidPart);
          if (( ((i+1) % 4) == 0 ) && (i != param_length-1) )
            g_strlcat(buffer, ":", MAX_PARAM_SIZE);
        }
        proto_tree_add_text(rtps_parameter_tree,
                        tvb,
                        offset,
                        param_length,
                        "%s",
                        buffer);
        break;
      }


      /* 0...2...........7...............15.............23...............31
       * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       * | PID_PARTICIPANT_LEASE_DURATION|            0x0008             |
       * +---------------+---------------+---------------+---------------+
       * |    long              NtpTime.seconds                          |
       * +---------------+---------------+---------------+---------------+
       * |    unsigned long     NtpTime.fraction                         |
       * +---------------+---------------+---------------+---------------+
       */
      case PID_PARTICIPANT_LEASE_DURATION:
        ENSURE_LENGTH(8);
        rtps_util_add_ntp_time(rtps_parameter_tree,
                        tvb,
                        offset,
                        little_endian,
                        "duration",
                        buffer,
                        MAX_PARAM_SIZE);
        break;


      /* 0...2...........7...............15.............23...............31
       * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       * | PID_TIME_BASED_FILTER         |            0x0008             |
       * +---------------+---------------+---------------+---------------+
       * |    long              NtpTime.seconds                          |
       * +---------------+---------------+---------------+---------------+
       * |    unsigned long     NtpTime.fraction                         |
       * +---------------+---------------+---------------+---------------+
       */
      case PID_TIME_BASED_FILTER:
        ENSURE_LENGTH(8);
        rtps_util_add_ntp_time(rtps_parameter_tree,
                        tvb,
                        offset,
                        little_endian,
                        "minimum_separation",
                        buffer,
                        MAX_PARAM_SIZE);
        break;

      /* 0...2...........7...............15.............23...............31
       * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       * | PID_TOPIC_NAME                |            length             |
       * +---------------+---------------+---------------+---------------+
       * |    unsigned long     String.length                            |
       * +---------------+---------------+---------------+---------------+
       * |   str[0]      |   str[1]      |   str[2]      |   str[3]      |
       * +---------------+---------------+---------------+---------------+
       * |                              ...                              |
       * +---------------+---------------+---------------+---------------+
       */
      case PID_TOPIC_NAME:
        rtps_util_add_string(rtps_parameter_tree,
                        tvb,
                        offset,
                        hf_rtps_param_topic_name,
                        little_endian,
                        NULL,           /* No label, use hf param */
                        buffer,
                        MAX_PARAM_SIZE);
        break;


      /* 0...2...........7...............15.............23...............31
       * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       * | PID_OWNERSHIP_STRENGTH        |            0x0004             |
       * +---------------+---------------+---------------+---------------+
       * |    long              strength                                 |
       * +---------------+---------------+---------------+---------------+
       */
      case PID_OWNERSHIP_STRENGTH:
        ENSURE_LENGTH(4);
        rtps_util_add_long(rtps_parameter_tree,
                        tvb,
                        offset,
                        hf_rtps_param_strength,
                        little_endian,
                        FALSE,  /* Is Hex ? */
                        TRUE,   /* Is Signed ? */
                        NULL,   /* No Label, use the protocol item ID */
                        buffer,
                        MAX_PARAM_SIZE);
        break;

      /* 0...2...........7...............15.............23...............31
       * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       * | PID_TYPE_NAME                 |            length             |
       * +---------------+---------------+---------------+---------------+
       * |    unsigned long     String.length                            |
       * +---------------+---------------+---------------+---------------+
       * |   str[0]      |   str[1]      |   str[2]      |   str[3]      |
       * +---------------+---------------+---------------+---------------+
       * |                              ...                              |
       * +---------------+---------------+---------------+---------------+
       */
      case PID_TYPE_NAME:
        rtps_util_add_string(rtps_parameter_tree,
                        tvb,
                        offset,
                        hf_rtps_param_type_name,
                        little_endian,
                        NULL,           /* No label, use hf param */
                        buffer,
                        MAX_PARAM_SIZE);
        break;



      /* 0...2...........7...............15.............23...............31
       * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       * | PID_XXXXXXXXXXX               |            0x0004             |
       * +---------------+---------------+---------------+---------------+
       * |    long              port                                     |
       * +---------------+---------------+---------------+---------------+
       */
      case PID_METATRAFFIC_MULTICAST_PORT:
      case PID_METATRAFFIC_UNICAST_PORT:
      case PID_DEFAULT_UNICAST_PORT:
        ENSURE_LENGTH(4);
        rtps_util_add_port(rtps_parameter_tree,
                        tvb,
                        offset,
                        little_endian,
                        "port",
                        buffer,
                        MAX_PARAM_SIZE);
        break;



      /* 0...2...........7...............15.............23...............31
       * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       * | PID_EXPECTS_INLINE_QOS        |            0x0004             |
       * +---------------+---------------+---------------+---------------+
       * |    boolean    |       N O T      U S E D                      |
       * +---------------+---------------+---------------+---------------+
       */
      case PID_EXPECTS_INLINE_QOS:
        ENSURE_LENGTH(1);
        rtps_util_add_boolean(rtps_parameter_tree,
                        tvb,
                        offset,
                        "inline_qos",
                        buffer,
                        MAX_PARAM_SIZE);
        break;

      /* 0...2...........7...............15.............23...............31
       * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       * | PID_XXXXXXXXXXX               |            length             |
       * +---------------+---------------+---------------+---------------+
       * |    unsigned long     ip_address                               |
       * +---------------+---------------+---------------+---------------+
       */
      case PID_METATRAFFIC_MULTICAST_IPADDRESS:
      case PID_DEFAULT_UNICAST_IPADDRESS:
      case PID_MULTICAST_IPADDRESS:
      case PID_METATRAFFIC_UNICAST_IPADDRESS:
        rtps_util_add_ipv4_address_t(rtps_parameter_tree,
                        tvb,
                        offset,
                        little_endian,
                        "address",
                        buffer,
                        MAX_PARAM_SIZE);
        break;



      /* 0...2...........7...............15.............23...............31
       * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       * | PID_PROTOCOL_VERSION          |            0x0004             |
       * +---------------+---------------+---------------+---------------+
       * | uint8 major   | uint8 minor   |    N O T    U S E D           |
       * +---------------+---------------+---------------+---------------+
       */
      case PID_PROTOCOL_VERSION: {
        guint8 major = 0;
        guint8 minor = 0;

        ENSURE_LENGTH(2);
        major = tvb_get_guint8(tvb, offset);
        minor = tvb_get_guint8(tvb, offset+1);
        g_snprintf(buffer, MAX_PARAM_SIZE, "%d.%d", major, minor);
        proto_tree_add_text(rtps_parameter_tree,
                        tvb,
                        offset,
                        param_length,
                        "protocolVersion: %s",
                        buffer);
        break;
      }

      /* 0...2...........7...............15.............23...............31
       * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       * | PID_VENDOR_ID                 |            0x0004             |
       * +---------------+---------------+---------------+---------------+
       * | uint8 major   | uint8 minor   |    N O T    U S E D           |
       * +---------------+---------------+---------------+---------------+
       */
      case PID_VENDOR_ID:
        ENSURE_LENGTH(2);
        rtps_util_add_vendor_id(NULL,
                        tvb,
                        offset,
                        buffer,
                        MAX_PARAM_SIZE);
        proto_tree_add_text(rtps_parameter_tree,
                        tvb,
                        offset,
                        2,
                        "vendorId: %s",
                        buffer);

        break;


      /* 0...2...........7...............15.............23...............31
       * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       * | PID_RELIABILITY               |            0x0004             |
       * +---------------+---------------+---------------+---------------+
       * |    unsigned long     kind                                     |
       * +---------------+---------------+---------------+---------------+
       */
      case PID_RELIABILITY_OFFERED: /* Deprecated */
      case PID_RELIABILITY:
        ENSURE_LENGTH(4);
        rtps_util_add_kind_qos(rtps_parameter_tree,
                        tvb,
                        offset,
                        little_endian,
                        "kind",
                        reliability_qos_vals,
                        buffer,
                        MAX_PARAM_SIZE);
        break;


      /* 0...2...........7...............15.............23...............31
       * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       * | PID_LIVELINESS                |            0x000c             |
       * +---------------+---------------+---------------+---------------+
       * |    unsigned long     kind                                     |
       * +---------------+---------------+---------------+---------------+
       * |    long              NtpTime.seconds                          |
       * +---------------+---------------+---------------+---------------+
       * |    unsigned long     NtpTime.fraction                         |
       * +---------------+---------------+---------------+---------------+
       * NDDS 3.1 sends only 'kind' on the wire.
       *
       */
      case PID_LIVELINESS_OFFERED: /* Deprecated */
      case PID_LIVELINESS:
        ENSURE_LENGTH(12);
        rtps_util_add_liveliness_qos(rtps_parameter_tree,
                        tvb,
                        offset,
                        little_endian,
                        buffer,
                        MAX_PARAM_SIZE);
        break;


      /* 0...2...........7...............15.............23...............31
       * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       * | PID_DURABILITY                |            0x0004             |
       * +---------------+---------------+---------------+---------------+
       * |    unsigned long     kind                                     |
       * +---------------+---------------+---------------+---------------+
       */
      case PID_DURABILITY:
        ENSURE_LENGTH(4);
        rtps_util_add_kind_qos(rtps_parameter_tree,
                        tvb,
                        offset,
                        little_endian,
                        "durability",
                        durability_qos_vals,
                        buffer,
                        MAX_PARAM_SIZE);
        break;

      /* 0...2...........7...............15.............23...............31
       * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       * | PID_DURABILITY_SERVICE        |            0x0004             |
       * +---------------+---------------+---------------+---------------+
       * |    long              NtpTime.seconds                          |
       * +---------------+---------------+---------------+---------------+
       * |    unsigned long     NtpTime.fraction                         |
       * +---------------+---------------+---------------+---------------+
       * |    unsigned long     kind                                     |
       * +---------------+---------------+---------------+---------------+
       * |    long              history_depth                            |
       * +---------------+---------------+---------------+---------------+
       * |    long              max_samples                              |
       * +---------------+---------------+---------------+---------------+
       * |    long              max_instances                            |
       * +---------------+---------------+---------------+---------------+
       * |    long              max_samples_per_instance                 |
       * +---------------+---------------+---------------+---------------+
       */
      case PID_DURABILITY_SERVICE:
        ENSURE_LENGTH(28);
        rtps_util_add_durability_service_qos(rtps_parameter_tree,
                        tvb,
                        offset,
                        little_endian,
                        buffer,
                        MAX_PARAM_SIZE);
        break;


      /* 0...2...........7...............15.............23...............31
       * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       * | PID_OWNERSHIP                 |            0x0004             |
       * +---------------+---------------+---------------+---------------+
       * |    unsigned long     kind                                     |
       * +---------------+---------------+---------------+---------------+
       */
      case PID_OWNERSHIP_OFFERED: /* Deprecated */
      case PID_OWNERSHIP:
        ENSURE_LENGTH(4);
        rtps_util_add_kind_qos(rtps_parameter_tree,
                        tvb,
                        offset,
                        little_endian,
                        "kind",
                        ownership_qos_vals,
                        buffer,
                        MAX_PARAM_SIZE);
        break;


      /* 0...2...........7...............15.............23...............31
       * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       * | PID_TRANSPORT_PRIORITY        |            0x0004             |
       * +---------------+---------------+---------------+---------------+
       * |    unsigned long     value                                    |
       * +---------------+---------------+---------------+---------------+
       */
      case PID_TRANSPORT_PRIORITY:
        ENSURE_LENGTH(4);
        rtps_util_add_long(rtps_parameter_tree,
                        tvb,
                        offset,
                        -1,     /* No protocol ID, use label below */
                        little_endian,
                        FALSE,  /* Is Hex ? */
                        FALSE,  /* Is Signed ? */
                        "value",
                        buffer,
                        MAX_PARAM_SIZE);
        break;

      /* 0...2...........7...............15.............23...............31
       * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       * | PID_PRESENTATION              |            0x0008             |
       * +---------------+---------------+---------------+---------------+
       * |    unsigned long     kind                                     |
       * +---------------+---------------+---------------+---------------+
       * |   boolean     |   boolean     |      N O T    U S E D         |
       * +---------------+---------------+---------------+---------------+
       */
      case PID_PRESENTATION_OFFERED: /* Deprecated */
      case PID_PRESENTATION:
        ENSURE_LENGTH(6);
        g_strlcpy(buffer, "{ ", MAX_PARAM_SIZE);
        rtps_util_add_kind_qos(rtps_parameter_tree,
                        tvb,
                        offset,
                        little_endian,
                        "access_scope",
                        presentation_qos_vals,
                        buffer+strlen(buffer),
                        MAX_PARAM_SIZE-strlen(buffer));
        g_strlcat(buffer, ", ", MAX_PARAM_SIZE);
        rtps_util_add_boolean(rtps_parameter_tree,
                        tvb,
                        offset+4,
                        "coherent_access",
                        buffer+strlen(buffer),
                        MAX_PARAM_SIZE-strlen(buffer));
        g_strlcat(buffer, ", ", MAX_PARAM_SIZE);
        rtps_util_add_boolean(rtps_parameter_tree,
                        tvb,
                        offset+4,
                        "ordered_access",
                        buffer+strlen(buffer),
                        MAX_PARAM_SIZE-strlen(buffer));
        g_strlcat(buffer, " }", MAX_PARAM_SIZE);
        break;


      /* 0...2...........7...............15.............23...............31
       * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       * | PID_DEADLINE                  |            0x0008             |
       * +---------------+---------------+---------------+---------------+
       * |    long              NtpTime.seconds                          |
       * +---------------+---------------+---------------+---------------+
       * |    unsigned long     NtpTime.fraction                         |
       * +---------------+---------------+---------------+---------------+
       */
      case PID_DEADLINE_OFFERED: /* Deprecated */
      case PID_DEADLINE:
        ENSURE_LENGTH(8);
        rtps_util_add_ntp_time(rtps_parameter_tree,
                        tvb,
                        offset,
                        little_endian,
                        "period",
                        buffer,
                        MAX_PARAM_SIZE);
        break;

      /* 0...2...........7...............15.............23...............31
       * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       * | PID_DESTINATION_ORDER         |            0x0004             |
       * +---------------+---------------+---------------+---------------+
       * |    unsigned long     kind                                     |
       * +---------------+---------------+---------------+---------------+
       */
      case PID_DESTINATION_ORDER_OFFERED: /* Deprecated */
      case PID_DESTINATION_ORDER:
        ENSURE_LENGTH(4);
        rtps_util_add_kind_qos(rtps_parameter_tree,
                        tvb,
                        offset,
                        little_endian,
                        "kind",
                        destination_order_qos_vals,
                        buffer,
                        MAX_PARAM_SIZE);
        break;


      /* 0...2...........7...............15.............23...............31
       * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       * | PID_LATENCY_BUDGET            |            0x0008             |
       * +---------------+---------------+---------------+---------------+
       * |    long              NtpTime.seconds                          |
       * +---------------+---------------+---------------+---------------+
       * |    unsigned long     NtpTime.fraction                         |
       * +---------------+---------------+---------------+---------------+
       */
      case PID_LATENCY_BUDGET_OFFERED:
      case PID_LATENCY_BUDGET:
        ENSURE_LENGTH(8);
        rtps_util_add_ntp_time(rtps_parameter_tree,
                        tvb,
                        offset,
                        little_endian,
                        "duration",
                        buffer,
                        MAX_PARAM_SIZE);
        break;


      /* 0...2...........7...............15.............23...............31
       * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       * | PID_PARTITION                 |             length            |
       * +---------------+---------------+---------------+---------------+
       * |    unsigned long     sequence_size                            |
       * +---------------+---------------+---------------+---------------+
       * |    unsigned long     string[0].size                           |
       * +---------------+---------------+---------------+---------------+
       * | string[0][0]  | string[0][1]  | string[0][2]  | string[0][3]  |
       * +---------------+---------------+---------------+---------------+
       * |                              ...                              |
       * +---------------+---------------+---------------+---------------+
       * The value is a sequence of strings.
       */
      case PID_PARTITION_OFFERED:  /* Deprecated */
      case PID_PARTITION:
        ENSURE_LENGTH(4);
        rtps_util_add_seq_string(rtps_parameter_tree,
                        tvb,
                        offset,
                        little_endian,
                        param_length,
                        "name",
                        buffer,
                        MAX_PARAM_SIZE);
        break;

      /* 0...2...........7...............15.............23...............31
       * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       * | PID_LIFESPAN                  |            0x0008             |
       * +---------------+---------------+---------------+---------------+
       * |    long              NtpTime.seconds                          |
       * +---------------+---------------+---------------+---------------+
       * |    unsigned long     NtpTime.fraction                         |
       * +---------------+---------------+---------------+---------------+
       */
      case PID_LIFESPAN:
        ENSURE_LENGTH(8);
        rtps_util_add_ntp_time(rtps_parameter_tree,
                        tvb,
                        offset,
                        little_endian,
                        "duration",
                        buffer,
                        MAX_PARAM_SIZE);

        break;

      /* 0...2...........7...............15.............23...............31
       * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       * | PID_USER_DATA                 |             length            |
       * +---------------+---------------+---------------+---------------+
       * |    unsigned long     sequence_size                            |
       * +---------------+---------------+---------------+---------------+
       * |   octet[0]    |   octet[1]    |   octet[2]    |   octet[3]    |
       * +---------------+---------------+---------------+---------------+
       * |                              ...                              |
       * +---------------+---------------+---------------+---------------+
       */
      case PID_USER_DATA:
        ENSURE_LENGTH(4);
        rtps_util_add_seq_octets(rtps_parameter_tree,
                        tvb,
                        offset,
                        little_endian,
                        param_length,
                        hf_rtps_param_user_data,
                        buffer,
                        MAX_PARAM_SIZE);

        break;

      /* 0...2...........7...............15.............23...............31
       * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       * | PID_GROUP_DATA                |             length            |
       * +---------------+---------------+---------------+---------------+
       * |    unsigned long     sequence_size                            |
       * +---------------+---------------+---------------+---------------+
       * |   octet[0]    |   octet[1]    |   octet[2]    |   octet[3]    |
       * +---------------+---------------+---------------+---------------+
       * |                              ...                              |
       * +---------------+---------------+---------------+---------------+
       */
      case PID_GROUP_DATA:
        ENSURE_LENGTH(4);
        rtps_util_add_seq_octets(rtps_parameter_tree,
                        tvb,
                        offset,
                        little_endian,
                        param_length,
                        hf_rtps_param_group_data,
                        buffer,
                        MAX_PARAM_SIZE);
        break;

      /* 0...2...........7...............15.............23...............31
       * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       * | PID_TOPIC_DATA                |             length            |
       * +---------------+---------------+---------------+---------------+
       * |    unsigned long     sequence_size                            |
       * +---------------+---------------+---------------+---------------+
       * |   octet[0]    |   octet[1]    |   octet[2]    |   octet[3]    |
       * +---------------+---------------+---------------+---------------+
       * |                              ...                              |
       * +---------------+---------------+---------------+---------------+
       */
     case PID_TOPIC_DATA:
        ENSURE_LENGTH(4);
        rtps_util_add_seq_octets(rtps_parameter_tree,
                        tvb,
                        offset,
                        little_endian,
                        param_length,
                        hf_rtps_param_topic_data,
                        buffer,
                        MAX_PARAM_SIZE);
        break;

      /* 0...2...........7...............15.............23...............31
       * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       * | PID_UNICAST_LOCATOR           |            0x0018             |
       * +---------------+---------------+---------------+---------------+
       * |    long              kind                                     |
       * +---------------+---------------+---------------+---------------+
       * |    long              port                                     |
       * +---------------+---------------+---------------+---------------+
       * | ipv6addr[0]   | ipv6addr[1]   | ipv6addr[2]   | ipv6addr[3]   |
       * +---------------+---------------+---------------+---------------+
       * | ipv6addr[4]   | ipv6addr[5]   | ipv6addr[6]   | ipv6addr[7]   |
       * +---------------+---------------+---------------+---------------+
       * | ipv6addr[8]   | ipv6addr[9]   | ipv6addr[10]  | ipv6addr[11]  |
       * +---------------+---------------+---------------+---------------+
       * | ipv6addr[12]  | ipv6addr[13]  | ipv6addr[14]  | ipv6addr[15]  |
       * +---------------+---------------+---------------+---------------+
       */
     case PID_UNICAST_LOCATOR:
        ENSURE_LENGTH(24);
        rtps_util_add_locator_t(rtps_parameter_tree,
                        tvb,
                        offset,
                        little_endian,
                        "locator",
                        buffer,
                        MAX_PARAM_SIZE);

        break;

      /* 0...2...........7...............15.............23...............31
       * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       * | PID_DEFAULT_MULTICAST_LOCATOR |            0x0018             |
       * +---------------+---------------+---------------+---------------+
       * |    long              kind                                     |
       * +---------------+---------------+---------------+---------------+
       * |    long              port                                     |
       * +---------------+---------------+---------------+---------------+
       * | ipv6addr[0]   | ipv6addr[1]   | ipv6addr[2]   | ipv6addr[3]   |
       * +---------------+---------------+---------------+---------------+
       * | ipv6addr[4]   | ipv6addr[5]   | ipv6addr[6]   | ipv6addr[7]   |
       * +---------------+---------------+---------------+---------------+
       * | ipv6addr[8]   | ipv6addr[9]   | ipv6addr[10]  | ipv6addr[11]  |
       * +---------------+---------------+---------------+---------------+
       * | ipv6addr[12]  | ipv6addr[13]  | ipv6addr[14]  | ipv6addr[15]  |
       * +---------------+---------------+---------------+---------------+
       */
     case PID_DEFAULT_MULTICAST_LOCATOR:
        ENSURE_LENGTH(24);
        rtps_util_add_locator_t(rtps_parameter_tree,
                        tvb,
                        offset,
                        little_endian,
                        "locator",
                        buffer,
                        MAX_PARAM_SIZE);

        break;


      /* 0...2...........7...............15.............23...............31
       * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       * | PID_MULTICAST_LOCATOR         |            0x0018             |
       * +---------------+---------------+---------------+---------------+
       * |    long              kind                                     |
       * +---------------+---------------+---------------+---------------+
       * |    long              port                                     |
       * +---------------+---------------+---------------+---------------+
       * | ipv6addr[0]   | ipv6addr[1]   | ipv6addr[2]   | ipv6addr[3]   |
       * +---------------+---------------+---------------+---------------+
       * | ipv6addr[4]   | ipv6addr[5]   | ipv6addr[6]   | ipv6addr[7]   |
       * +---------------+---------------+---------------+---------------+
       * | ipv6addr[8]   | ipv6addr[9]   | ipv6addr[10]  | ipv6addr[11]  |
       * +---------------+---------------+---------------+---------------+
       * | ipv6addr[12]  | ipv6addr[13]  | ipv6addr[14]  | ipv6addr[15]  |
       * +---------------+---------------+---------------+---------------+
       */
     case PID_MULTICAST_LOCATOR:
        ENSURE_LENGTH(24);
        rtps_util_add_locator_t(rtps_parameter_tree,
                        tvb,
                        offset,
                        little_endian,
                        "locator",
                        buffer,
                        MAX_PARAM_SIZE);

        break;

      /* 0...2...........7...............15.............23...............31
       * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       * | PID_DEFAULT_UNICAST_LOCATOR   |            0x0018             |
       * +---------------+---------------+---------------+---------------+
       * |    long              kind                                     |
       * +---------------+---------------+---------------+---------------+
       * |    long              port                                     |
       * +---------------+---------------+---------------+---------------+
       * | ipv6addr[0]   | ipv6addr[1]   | ipv6addr[2]   | ipv6addr[3]   |
       * +---------------+---------------+---------------+---------------+
       * | ipv6addr[4]   | ipv6addr[5]   | ipv6addr[6]   | ipv6addr[7]   |
       * +---------------+---------------+---------------+---------------+
       * | ipv6addr[8]   | ipv6addr[9]   | ipv6addr[10]  | ipv6addr[11]  |
       * +---------------+---------------+---------------+---------------+
       * | ipv6addr[12]  | ipv6addr[13]  | ipv6addr[14]  | ipv6addr[15]  |
       * +---------------+---------------+---------------+---------------+
       */
     case PID_DEFAULT_UNICAST_LOCATOR:
        ENSURE_LENGTH(24);
        rtps_util_add_locator_t(rtps_parameter_tree,
                        tvb,
                        offset,
                        little_endian,
                        "locator",
                        buffer,
                        MAX_PARAM_SIZE);

        break;

      /* 0...2...........7...............15.............23...............31
       * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       * | PID_METATRAFFIC_UNICAST_LOC...|            0x0018             |
       * +---------------+---------------+---------------+---------------+
       * |    long              kind                                     |
       * +---------------+---------------+---------------+---------------+
       * |    long              port                                     |
       * +---------------+---------------+---------------+---------------+
       * | ipv6addr[0]   | ipv6addr[1]   | ipv6addr[2]   | ipv6addr[3]   |
       * +---------------+---------------+---------------+---------------+
       * | ipv6addr[4]   | ipv6addr[5]   | ipv6addr[6]   | ipv6addr[7]   |
       * +---------------+---------------+---------------+---------------+
       * | ipv6addr[8]   | ipv6addr[9]   | ipv6addr[10]  | ipv6addr[11]  |
       * +---------------+---------------+---------------+---------------+
       * | ipv6addr[12]  | ipv6addr[13]  | ipv6addr[14]  | ipv6addr[15]  |
       * +---------------+---------------+---------------+---------------+
       */
     case PID_METATRAFFIC_UNICAST_LOCATOR:
        ENSURE_LENGTH(24);
        rtps_util_add_locator_t(rtps_parameter_tree,
                        tvb,
                        offset,
                        little_endian,
                        "locator",
                        buffer,
                        MAX_PARAM_SIZE);

        break;

      /* 0...2...........7...............15.............23...............31
       * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       * | PID_METATRAFFIC_MULTICAST_L...|            0x0018             |
       * +---------------+---------------+---------------+---------------+
       * |    long              kind                                     |
       * +---------------+---------------+---------------+---------------+
       * |    long              port                                     |
       * +---------------+---------------+---------------+---------------+
       * | ipv6addr[0]   | ipv6addr[1]   | ipv6addr[2]   | ipv6addr[3]   |
       * +---------------+---------------+---------------+---------------+
       * | ipv6addr[4]   | ipv6addr[5]   | ipv6addr[6]   | ipv6addr[7]   |
       * +---------------+---------------+---------------+---------------+
       * | ipv6addr[8]   | ipv6addr[9]   | ipv6addr[10]  | ipv6addr[11]  |
       * +---------------+---------------+---------------+---------------+
       * | ipv6addr[12]  | ipv6addr[13]  | ipv6addr[14]  | ipv6addr[15]  |
       * +---------------+---------------+---------------+---------------+
       */
     case PID_METATRAFFIC_MULTICAST_LOCATOR:
        ENSURE_LENGTH(24);
        rtps_util_add_locator_t(rtps_parameter_tree,
                        tvb,
                        offset,
                        little_endian,
                        "locator",
                        buffer,
                        MAX_PARAM_SIZE);

        break;

      /* 0...2...........7...............15.............23...............31
       * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       * | PID_PARTICIPANT_MANUAL_LIVE...|            0x0004             |
       * +---------------+---------------+---------------+---------------+
       * |    long              livelinessEpoch                          |
       * +---------------+---------------+---------------+---------------+
       */
      case PID_PARTICIPANT_BUILTIN_ENDPOINTS:
      case PID_PARTICIPANT_MANUAL_LIVELINESS_COUNT:
        ENSURE_LENGTH(4);
        rtps_util_add_long(rtps_parameter_tree,
                        tvb,
                        offset,
                        -1,     /* No protocol ID, use label below */
                        little_endian,
                        TRUE,   /* Is Hex ? */
                        FALSE,  /* Is Signed ? */
                        "value",
                        buffer,
                        MAX_PARAM_SIZE);
        break;

      /* 0...2...........7...............15.............23...............31
       * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       * | PID_HISTORY                   |            0x0004             |
       * +---------------+---------------+---------------+---------------+
       * |    long              kind                                     |
       * +---------------+---------------+---------------+---------------+
       * |    long              depth                                    |
       * +---------------+---------------+---------------+---------------+
       */
      case PID_HISTORY:
        ENSURE_LENGTH(8);
        g_strlcpy(buffer, "{ ", MAX_PARAM_SIZE);
        rtps_util_add_kind_qos(rtps_parameter_tree,
                        tvb,
                        offset,
                        little_endian,
                        "kind",
                        history_qos_vals,
                        buffer+strlen(buffer),
                        MAX_PARAM_SIZE-strlen(buffer));
        g_strlcat(buffer, ", ", MAX_PARAM_SIZE);

        rtps_util_add_long(rtps_parameter_tree,
                        tvb,
                        offset+4,
                        -1,     /* No protocol ID, use label below */
                        little_endian,
                        FALSE,  /* Is Hex ? */
                        TRUE,  /* Is Signed ? */
                        "depth",
                        buffer + strlen(buffer),
                        MAX_PARAM_SIZE-strlen(buffer));
        g_strlcat(buffer, " }", MAX_PARAM_SIZE);
        break;


      /* 0...2...........7...............15.............23...............31
       * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       * | PID_RESOURCE_LIMIT            |            0x0004             |
       * +---------------+---------------+---------------+---------------+
       * |    long              max_samples                              |
       * +---------------+---------------+---------------+---------------+
       * |    long              max_instances                            |
       * +---------------+---------------+---------------+---------------+
       * |    long              max_samples_per_instances                |
       * +---------------+---------------+---------------+---------------+
       */
      case PID_RESOURCE_LIMIT:
        ENSURE_LENGTH(12);
        g_strlcpy(buffer, "{ ", MAX_PARAM_SIZE);
        rtps_util_add_long(rtps_parameter_tree,
                        tvb,
                        offset,
                        -1,     /* No protocol ID, use label below */
                        little_endian,
                        FALSE,  /* Is Hex ? */
                        TRUE,  /* Is Signed ? */
                        "max_samples",
                        buffer + strlen(buffer),
                        MAX_PARAM_SIZE-strlen(buffer));
        g_strlcat(buffer, ", ", MAX_PARAM_SIZE);
        rtps_util_add_long(rtps_parameter_tree,
                        tvb,
                        offset+4,
                        -1,     /* No protocol ID, use label below */
                        little_endian,
                        FALSE,  /* Is Hex ? */
                        TRUE,  /* Is Signed ? */
                        "max_instances",
                        buffer + strlen(buffer),
                        MAX_PARAM_SIZE-strlen(buffer));
        g_strlcat(buffer, ", ", MAX_PARAM_SIZE);

        rtps_util_add_long(rtps_parameter_tree,
                        tvb,
                        offset+8,
                        -1,     /* No protocol ID, use label below */
                        little_endian,
                        FALSE,  /* Is Hex ? */
                        TRUE,  /* Is Signed ? */
                        "max_samples_per_instances",
                        buffer + strlen(buffer),
                        MAX_PARAM_SIZE-strlen(buffer));
        g_strlcat(buffer, " }", MAX_PARAM_SIZE);
        break;


      /* 0...2...........7...............15.............23...............31
       * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       * | PID_CONTENT_FILTER_PROPERTY   |            length             |
       * +---------------+---------------+---------------+---------------+
       * |    unsigned long     String1.length                           |
       * +---------------+---------------+---------------+---------------+
       * |   str1[0]     |   str1[1]     |   str1[2]     |   str1[3]     |
       * +---------------+---------------+---------------+---------------+
       * |                              ...                              |
       * +---------------+---------------+---------------+---------------+
       * |    unsigned long     String2.length                           |
       * +---------------+---------------+---------------+---------------+
       * |   str2[0]     |   str2[1]     |   str2[2]     |   str2[3]     |
       * +---------------+---------------+---------------+---------------+
       * |                              ...                              |
       * +---------------+---------------+---------------+---------------+
       * |    unsigned long     String3.length                           |
       * +---------------+---------------+---------------+---------------+
       * |   str3[0]     |   str3[1]     |   str3[2]     |   str3[3]     |
       * +---------------+---------------+---------------+---------------+
       * |                              ...                              |
       * +---------------+---------------+---------------+---------------+
       * |    unsigned long     String4.length                           |
       * +---------------+---------------+---------------+---------------+
       * |   str4[0]     |   str4[1]     |   str4[2]     |   str4[3]     |
       * +---------------+---------------+---------------+---------------+
       * |                              ...                              |
       * +---------------+---------------+---------------+---------------+
       * |                              ...                              |
       * |                      Filter Parameters                        |
       * |                              ...                              |
       * +---------------+---------------+---------------+---------------+
       *
       * String1: ContentFilterName
       * String2: RelatedTopicName
       * String3: FilterName
       * String4: FilterExpression
       * FilterParameters: sequence of Strings
       *
       * Note: those strings starts all to a word-aligned (4 bytes) offset
       */
      case PID_CONTENT_FILTER_PROPERTY: {
        guint32 temp_offset = offset;
        ENSURE_LENGTH(20);
        temp_offset = rtps_util_add_string(rtps_parameter_tree,
                        tvb,
                        temp_offset,
                        hf_rtps_param_content_filter_name,
                        little_endian,
                        NULL,           /* No label, use hf param */
                        buffer,
                        MAX_PARAM_SIZE);
        temp_offset = rtps_util_add_string(rtps_parameter_tree,
                        tvb,
                        temp_offset,
                        hf_rtps_param_related_topic_name,
                        little_endian,
                        NULL,
                        NULL,
                        0);
        temp_offset = rtps_util_add_string(rtps_parameter_tree,
                        tvb,
                        temp_offset,
                        hf_rtps_param_filter_name,
                        little_endian,
                        NULL,
                        NULL,
                        0);
        temp_offset = rtps_util_add_string(rtps_parameter_tree,
                        tvb,
                        temp_offset,
                        -1,
                        little_endian,
                        "filterExpression",
                        NULL,
                        0);
        temp_offset = rtps_util_add_seq_string(rtps_parameter_tree,
                        tvb,
                        temp_offset,
                        little_endian,
                        param_length,
                        "filterParameters",
                        NULL,
                        0);
        break;
      }

      /* 0...2...........7...............15.............23...............31
       * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       * | PID_PROPERTY_LIST             |            length             |
       * +---------------+---------------+---------------+---------------+
       * |    unsigned long     Seq.Length                               |
       * +---------------+---------------+---------------+---------------+
       * |                              ...                              |
       * |                           Property 1                          |
       * |                              ...                              |
       * +---------------+---------------+---------------+---------------+
       * |                              ...                              |
       * |                           Property 2                          |
       * |                              ...                              |
       * +---------------+---------------+---------------+---------------+
       * |                              ...                              |
       * |                           Property n                          |
       * |                              ...                              |
       * +---------------+---------------+---------------+---------------+
       *
       * IDL:
       *    struct PROPERTY {
       *        String Name;
       *        String Value;
       *    };
       *
       *    struct PROPERTY_LIST {
       *        Sequence<PROPERTY> PropertyList;
       *    };
       *
       */
      case PID_PROPERTY_LIST:
      case PID_PROPERTY_LIST_OLD:
        ENSURE_LENGTH(4);
        {
          guint32 prev_offset;
          guint32 temp_offset;
          guint8 tempName[MAX_PARAM_SIZE];
          guint8 tempValue[MAX_PARAM_SIZE];
          guint32 seq_size = NEXT_guint32(tvb, offset, little_endian);
          g_snprintf(buffer, MAX_PARAM_SIZE, "%d properties", seq_size);
          if (seq_size > 0) {
            proto_tree_add_text(rtps_parameter_tree,
                        tvb,
                        offset,
                        0,
                     /*  123456789012345678901234567890|123456789012345678901234567890 */
                        "        Property Name         |       Property Value");

            proto_tree_add_text(rtps_parameter_tree,
                        tvb,
                        offset,
                        0,
                     /*  123456789012345678901234567890|123456789012345678901234567890 */
                        "------------------------------|------------------------------");

            temp_offset = offset+4;
            while(seq_size-- > 0) {
              prev_offset = temp_offset;
              temp_offset = rtps_util_add_string(NULL,
                          tvb,
                          temp_offset,
                          -1,
                          little_endian,
                          NULL,
                          tempName,
                          MAX_PARAM_SIZE);
              temp_offset = rtps_util_add_string(NULL,
                          tvb,
                          temp_offset,
                          -1,
                          little_endian,
                          NULL,
                          tempValue,
                          MAX_PARAM_SIZE);
              proto_tree_add_text(rtps_parameter_tree,
                          tvb,
                          prev_offset,
                          temp_offset - prev_offset,
                          "%-29s | %-29s",
                          tempName,
                          tempValue);
            }
          }
        }
        break;

      /* 0...2...........7...............15.............23...............31
       * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       * | PID_CONTENT_FILTER_INFO       |            length             |
       * +---------------+---------------+---------------+---------------+
       * |                              ...                              |
       * +---------------+---------------+---------------+---------------+
       *
       * IDL:
       *     struct CONTENT_FILTER_SIGNATURE {
       *         sequence<long>  filterBitmap;
       *         sequence<FILTER_SIGNATURE, 4> filterSignature;
       *     }
       *
       * where:
       *     struct FILTER_SIGNATURE {
       *         long filterSignature[4];
       *     }
       */
      case PID_CONTENT_FILTER_INFO: {
        guint32 temp_offset = offset;
        guint32 prev_offset;
        guint32 fs_elem;
        guint32 fs[4];
        ENSURE_LENGTH(8);

        /* Dissect filter bitmap */
        temp_offset = rtps_util_add_seq_ulong(rtps_parameter_tree,
                        tvb,
                        offset,
                        little_endian,
                        param_length,
                        TRUE,           /* is_hex */
                        FALSE,          /* filterSignature: is_signed */
                        "filterBitmap");

        /* Dissect sequence of FILTER_SIGNATURE */
        fs_elem = NEXT_guint32(tvb, temp_offset, little_endian);
        temp_offset += 4;
        while (fs_elem-- > 0) {
            prev_offset = temp_offset;
            /* Dissect the next FILTER_SIGNATURE object */
            fs[0] = NEXT_guint32(tvb, temp_offset, little_endian);
            temp_offset += 4;
            fs[1] = NEXT_guint32(tvb, temp_offset, little_endian);
            temp_offset += 4;
            fs[2] = NEXT_guint32(tvb, temp_offset, little_endian);
            temp_offset += 4;
            fs[3] = NEXT_guint32(tvb, temp_offset, little_endian);
            temp_offset += 4;
            proto_tree_add_text(rtps_parameter_tree,
                          tvb,
                          prev_offset,
                          temp_offset - prev_offset,
                          "filterSignature: %08x %08x %08x %08x",
                          fs[0], fs[1], fs[2], fs[3]);
        }

        break;
      }


      /* 0...2...........7...............15.............23...............31
       * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       * | PID_COHERENT_SET              |            length             |
       * +---------------+---------------+---------------+---------------+
       * |                                                               |
       * + SequenceNumber seqNumber                                      +
       * |                                                               |
       * +---------------+---------------+---------------+---------------+
       */
      case PID_COHERENT_SET:
        ENSURE_LENGTH(8);
        rtps_util_add_seq_number(rtps_parameter_tree,
                        tvb,
                        offset,
                        little_endian,
                        "sequenceNumber");
        break;


      /* 0...2...........7...............15.............23...............31
       * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       * | PID_BUILTIN_ENDPOINT_SET      |            length             |
       * +---------------+---------------+---------------+---------------+
       * |    long              value                                    |
       * +---------------+---------------+---------------+---------------+
       */
      case PID_BUILTIN_ENDPOINT_SET: {
        guint32 data;
        guint32 datamask;
        char bitbuf[33];
        int i;
        ENSURE_LENGTH(4);
        data = NEXT_guint32(tvb, offset, little_endian);
        for (i = 0; i < 32; ++i) {
          datamask = (1 << (31-i));
          bitbuf[i] = ((data & datamask) == datamask) ? '1':'0';
        }
        bitbuf[i] = '\0';
        proto_tree_add_text(rtps_parameter_tree,
                        tvb,
                        offset,
                        4,
                        "value: %08x (%s)",
                        data, bitbuf);
        break;
      }

      /* 0...2...........7...............15.............23...............31
       * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       * | PID_TYPE_MAX_SIZE_SERIALIZED  |            length             |
       * +---------------+---------------+---------------+---------------+
       * |    long              value                                    |
       * +---------------+---------------+---------------+---------------+
       */
      case PID_TYPE_MAX_SIZE_SERIALIZED:
        ENSURE_LENGTH(4);
        rtps_util_add_long(rtps_parameter_tree,
                        tvb,
                        offset,
                        -1,     /* No protocol ID, use label below */
                        little_endian,
                        FALSE,  /* Is Hex ? */
                        FALSE,  /* Is Signed ? */
                        "value",
                        buffer,
                        MAX_PARAM_SIZE);
        break;



      /* 0...2...........7...............15.............23...............31
       * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       * | PID_ORIGINAL_WRITER_INFO      |            length             |
       * +---------------+---------------+---------------+---------------+
       * |                                                               |
       * +-                                                             -+
       * |    octet[12] guidPrefix                                       |
       * +-                                                             -+
       * |                                                               |
       * +---------------+---------------+---------------+---------------+
       * |    octet[4]  entityId                                         |
       * +---------------+---------------+---------------+---------------+
       * |                                                               |
       * + SequenceNumber writerSeqNum                                   +
       * |                                                               |
       * +---------------+---------------+---------------+---------------+
       */
      case PID_ORIGINAL_WRITER_INFO:
        ENSURE_LENGTH(16);
        rtps_util_add_guid_prefix(rtps_parameter_tree,
                        tvb,
                        offset,
                        hf_rtps_sm_guid_prefix,
                        hf_rtps_sm_host_id,
                        hf_rtps_sm_app_id,
                        hf_rtps_sm_counter,
                        "virtualGUIDPrefix",
                        NULL,
                        0);
        rtps_util_add_entity_id(rtps_parameter_tree,
                        tvb,
                        offset+12,
                        hf_rtps_sm_entity_id,
                        hf_rtps_sm_entity_id_key,
                        hf_rtps_sm_entity_id_kind,
                        ett_rtps_entity,
                        "virtualGUIDSuffix",
                        NULL);

        /* Sequence number */
        rtps_util_add_seq_number(rtps_parameter_tree,
                                tvb,
                                offset+16,
                                little_endian,
                                "virtualSeqNumber");
        break;

      /* 0...2...........7...............15.............23...............31
       * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       * | PID_ENTITY_NAME               |            length             |
       * +---------------+---------------+---------------+---------------+
       * |    unsigned long     String.length                            |
       * +---------------+---------------+---------------+---------------+
       * |   str[0]      |   str[1]      |   str[2]      |   str[3]      |
       * +---------------+---------------+---------------+---------------+
       * |                              ...                              |
       * +---------------+---------------+---------------+---------------+
       */
      case PID_ENTITY_NAME:
        rtps_util_add_string(rtps_parameter_tree,
                        tvb,
                        offset,
                        hf_rtps_param_entity_name,
                        little_endian,
                        NULL,           /* No label, use hf param */
                        buffer,
                        MAX_PARAM_SIZE);
        break;


      /* 0...2...........7...............15.............23...............31
       * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       * | PID_PARTICIPANT_GUID          |            0x0010             |
       * | PID_ENDPOINT_GUID             |                               |
       * +---------------+---------------+---------------+---------------+
       * |    guid[0]    |    guid[1]    |    guid[2]    |   guid[3]     |
       * +---------------+---------------+---------------+---------------+
       * |    guid[4]    |    guid[5]    |    guid[6]    |   guid[7]     |
       * +---------------+---------------+---------------+---------------+
       * |    guid[8]    |    guid[9]    |    guid[10]   |   guid[11]    |
       * +---------------+---------------+---------------+---------------+
       * |    guid[12]   |    guid[13]   |    guid[14]   |   guid[15]    |
       * +---------------+---------------+---------------+---------------+
       */
      case PID_PARTICIPANT_GUID:
      case PID_ENDPOINT_GUID:
        ENSURE_LENGTH(16);
        rtps_util_add_generic_guid(rtps_parameter_tree,
                        tvb,
                        offset,
                        "GUID",
                        buffer,
                        MAX_PARAM_SIZE);

        break;

      /* 0...2...........7...............15.............23...............31
       * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       * | PID_PARTICIPANT_ENTITY_ID     |            0x0004             |
       * +---------------+---------------+---------------+---------------+
       * |   entity[0]   |   entity[1]   |   entity[2]   |  entity[3]    |
       * +---------------+---------------+---------------+---------------+
       */
      case PID_PARTICIPANT_ENTITY_ID:
        ENSURE_LENGTH(4);
        rtps_util_add_generic_entity_id(rtps_parameter_tree,
                        tvb,
                        offset,
                        "Participant entity ID",
                        buffer,
                        MAX_PARAM_SIZE);
        break;

      /* 0...2...........7...............15.............23...............31
       * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       * | PID_GROUP_GUID                |            0x0010             |
       * +---------------+---------------+---------------+---------------+
       * |    guid[0]    |    guid[1]    |    guid[2]    |   guid[3]     |
       * +---------------+---------------+---------------+---------------+
       * |    guid[4]    |    guid[5]    |    guid[6]    |   guid[7]     |
       * +---------------+---------------+---------------+---------------+
       * |    guid[8]    |    guid[9]    |    guid[10]   |   guid[11]    |
       * +---------------+---------------+---------------+---------------+
       * |    guid[12]   |    guid[13]   |    guid[14]   |   guid[15]    |
       * +---------------+---------------+---------------+---------------+
       */
      case PID_GROUP_GUID:
        ENSURE_LENGTH(16);
        rtps_util_add_generic_guid(rtps_parameter_tree,
                        tvb,
                        offset,
                        "Group GUID",
                        buffer,
                        MAX_PARAM_SIZE);

        break;

      /* 0...2...........7...............15.............23...............31
       * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       * | PID_GROUP_ENTITY_ID           |            0x0004             |
       * +---------------+---------------+---------------+---------------+
       * |   entity[0]   |   entity[1]   |   entity[2]   |  entity[3]    |
       * +---------------+---------------+---------------+---------------+
       */
      case PID_GROUP_ENTITY_ID:
        ENSURE_LENGTH(4);

        rtps_util_add_generic_entity_id(rtps_parameter_tree,
                        tvb,
                        offset,
                        "Group entity ID",
                        buffer,
                        MAX_PARAM_SIZE);

        break;





      /* ==================================================================
       * Here are all the deprecated items.
       */

      case PID_PERSISTENCE:
        ENSURE_LENGTH(8);
        rtps_util_add_ntp_time(rtps_parameter_tree,
                        tvb,
                        offset,
                        little_endian,
                        "persistence",
                        buffer,
                        MAX_PARAM_SIZE);
        break;

      case PID_TYPE_CHECKSUM:
        ENSURE_LENGTH(4);
        rtps_util_add_long(rtps_parameter_tree,
                        tvb,
                        offset,
                        -1,
                        little_endian,
                        TRUE,   /* Is Hex? */
                        FALSE,  /* Is signed ? */
                        "checksum",
                        buffer,
                        MAX_PARAM_SIZE);
        break;

      case PID_EXPECTS_ACK:
        ENSURE_LENGTH(1);
        rtps_util_add_boolean(rtps_parameter_tree,
                        tvb,
                        offset,
                        "expectsAck",
                        buffer,
                        MAX_PARAM_SIZE);
        break;

      case PID_MANAGER_KEY: {
        int i = 0;
        char sep = ':';
        guint32 manager_key;

        buffer[0] = '\0';
        while (param_length >= 4) {
          manager_key = NEXT_guint32(tvb, offset, little_endian);
          g_snprintf(buffer+strlen(buffer),
                        MAX_PARAM_SIZE-(gulong)strlen(buffer),
                        "%c 0x%08x",
                        sep,
                        manager_key);
          proto_tree_add_text(rtps_parameter_tree,
                        tvb,
                        offset,
                        param_length,
                        "Key[%d]: 0x%X", i, manager_key);
          ++i;
          offset +=4;
          sep = ',';
          param_length -= 4; /* decrement count */
        }
        offset += param_length;
        break;
      }


      case PID_RECV_QUEUE_SIZE:
      case PID_SEND_QUEUE_SIZE:
        ENSURE_LENGTH(4);
        rtps_util_add_long(rtps_parameter_tree,
                        tvb,
                        offset,
                        -1,
                        little_endian,
                        TRUE,   /* Is Hex? */
                        FALSE,  /* Is signed ? */
                        "queueSize",
                        buffer,
                        MAX_PARAM_SIZE);
        break;


      case PID_VARGAPPS_SEQUENCE_NUMBER_LAST:
        ENSURE_LENGTH(4);
        rtps_util_add_seq_number(rtps_parameter_tree,
                        tvb,
                        offset,
                        little_endian,
                        "sequenceNumberLast");
        break;

      /* This is the default branch when we don't have enough information
       * on how to decode the parameter. It can be used also for known
       * parameters.
       */
      /* 0...2...........7...............15.............23...............31
       * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       * | <pid_id>                      |            0x0000             |
       * +---------------+---------------+---------------+---------------+
      */
      case PID_IS_RELIABLE:
      case PID_TYPE2_NAME:
      case PID_TYPE2_CHECKSUM:
      case PID_RELIABILITY_ENABLED:
        g_strlcpy(buffer, "[DEPRECATED] - Parameter not decoded", MAX_PARAM_SIZE);

      case PID_PAD:
        break;

      default:

        /* The following PIDS are vendor-specific */
        if (vendor_id == RTPS_VENDOR_RTI) {
          switch(parameter) {
            /* 0...2...........7...............15.............23...............31
             * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
             * | PID_PRODUCT_VERSION           |            length             |
             * +---------------+---------------+---------------+---------------+
             * | uint8 major   | uint8 minor   |    N O T    U S E D           |
             * +---------------+---------------+---------------+---------------+
             */
            case PID_PRODUCT_VERSION: {
              guint8 major = 0;
              guint8 minor = 0;
              guint8 release;
              guint8 revision;

              ENSURE_LENGTH(4);
              major = tvb_get_guint8(tvb, offset);
              minor = tvb_get_guint8(tvb, offset+1);
              release = tvb_get_guint8(tvb, offset+2);
              revision = tvb_get_guint8(tvb, offset+3);
              g_snprintf(buffer, MAX_PARAM_SIZE, "%d.%d%c rev%d",
                        major, minor, release, revision);
              proto_tree_add_text(rtps_parameter_tree,
                        tvb,
                        offset,
                        param_length,
                        "productVersion: %s",
                        buffer);
              break;
            }

            /* 0...2...........7...............15.............23...............31
             * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
             * | PID_PLUGIN_PROMISCUITY_KIND   |            length             |
             * +---------------+---------------+---------------+---------------+
             * | short  value                  |                               |
             * +---------------+---------------+---------------+---------------+
             */
            case PID_PLUGIN_PROMISCUITY_KIND: {
              guint32 val;
              ENSURE_LENGTH(4);
              val = NEXT_guint32(tvb, offset, little_endian);
              g_snprintf(buffer, MAX_PARAM_SIZE, "%s",
                        val_to_str(val, plugin_promiscuity_kind_vals,
                                   "unknown (%04x)"));

              proto_tree_add_text(rtps_parameter_tree,
                        tvb,
                        offset,
                        param_length,
                        "promiscuityKind: %s",
                        buffer);
              break;
            }

            /* 0...2...........7...............15.............23...............31
             * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
             * | PID_ENTITY_VIRTUAL_GUID       |            length             |
             * +---------------+---------------+---------------+---------------+
             * |                                                               |
             * +-                                                             -+
             * |    octet[12] guidPrefix                                       |
             * +-                                                             -+
             * |                                                               |
             * +---------------+---------------+---------------+---------------+
             * |    octet[4]  entityId                                         |
             * +---------------+---------------+---------------+---------------+
             */
            case PID_ENTITY_VIRTUAL_GUID:
              ENSURE_LENGTH(16);
              rtps_util_add_guid_prefix(rtps_parameter_tree,
                        tvb,
                        offset,
                        hf_rtps_sm_guid_prefix,
                        hf_rtps_sm_host_id,
                        hf_rtps_sm_app_id,
                        hf_rtps_sm_counter,
                        "virtualGUIDPrefix",
                        NULL,
                        0);
              rtps_util_add_entity_id(rtps_parameter_tree,
                        tvb,
                        offset+12,
                        hf_rtps_sm_entity_id,
                        hf_rtps_sm_entity_id_key,
                        hf_rtps_sm_entity_id_kind,
                        ett_rtps_entity,
                        "virtualGUIDSuffix",
                        NULL);
              break;


            /* 0...2...........7...............15.............23...............31
             * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
             * | PID_SERVICE_KIND              |            length             |
             * +---------------+---------------+---------------+---------------+
             * | long    value                                                 |
             * +---------------+---------------+---------------+---------------+
             */
            case PID_SERVICE_KIND: {
              guint32 val;
              ENSURE_LENGTH(4);
              val = NEXT_guint32(tvb, offset, little_endian);

              g_snprintf(buffer, MAX_PARAM_SIZE, "%s",
                        val_to_str(val, service_kind_vals, "unknown (%04x)"));

              proto_tree_add_text(rtps_parameter_tree,
                        tvb,
                        offset,
                        param_length,
                        "serviceKind: %s",
                        buffer);
              break;
            }

            /* 0...2...........7...............15.............23...............31
             * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
             * | PID_TYPECODE                  |            length             |
             * +---------------+---------------+---------------+---------------+
             * |                                                               |
             * +                    Type code description                      +
             * |                                                               |
             * +---------------+---------------+---------------+---------------+
             */
            case PID_TYPECODE:
              rtps_util_add_typecode(rtps_parameter_tree,
                        tvb,
                        offset,
                        little_endian,
                        0,      /* indent level */
                        0,      /* isPointer */
                        -1,     /* bitfield */
                        0,      /* isKey */
                        offset,
                        NULL,   /* name */
                        0,      /* not a seq field */
                        NULL,   /* not an array */
                        0);     /* ndds 4.0 hack: init to false */
              break;

            /* 0...2...........7...............15.............23...............31
             * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
             * | PID_DISABLE_POSITIVE_ACKS     |            length             |
             * +---------------+---------------+---------------+---------------+
             * | boolean value | = = = = = = = =  u n u s e d  = = = = = = = = |
             * +---------------+---------------+---------------+---------------+
             */
            case PID_DISABLE_POSITIVE_ACKS:
              ENSURE_LENGTH(1);
              rtps_util_add_boolean(rtps_parameter_tree,
                        tvb,
                        offset,
                        "disablePositiveAcks",
                        buffer,
                        MAX_PARAM_SIZE);
              break;

            /* 0...2...........7...............15.............23...............31
             * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
             * | PID_LOCATOR_FILTER_LIST       |            length             |
             * +---------------+---------------+---------------+---------------+
             * | unsigned long number_of_channels                              |
             * +---------------+---------------+---------------+---------------+
             * |                                                               |
             * ~ String filter_name                                            ~
             * |                                                               |
             * +---------------+---------------+---------------+---------------+
             * |                                                               |
             * ~ LocatorList                                                   ~ <----------+
             * |                                                               |    Repeat  |
             * +---------------+---------------+---------------+---------------+    For each|
             * |                                                               |    Channel |
             * ~ String filter_expression                                      ~            |
             * |                                                               |            |
             * +---------------+---------------+---------------+---------------+ <----------+
             */
            case PID_LOCATOR_FILTER_LIST: {
              guint32 number_of_channels = 0;
              proto_tree *channel_tree = NULL;
              proto_item *ti_channel = NULL;
              char temp_buff[MAX_LABEL_SIZE];
              guint32 ch;
              gint old_offset;
              guint32 off = offset;

              ENSURE_LENGTH(4);
              number_of_channels = NEXT_guint32(tvb, off, little_endian);
              g_snprintf(buffer, MAX_PARAM_SIZE, "%d channels", number_of_channels);
              off += 4;

              if (number_of_channels == 0) {
                /* Do not dissect the rest */
                proto_tree_add_text(rtps_parameter_tree,
                        tvb,
                        off-4,
                        4,
                        "numberOfChannels: %d", number_of_channels);
                break;
              }

              /* filter name */
              off = rtps_util_add_string(rtps_parameter_tree,
                tvb,
                off,
                -1,             /* hf_item not set */
                little_endian,
                "filterName",   /* label */
                NULL,           /* buffer not set */
                0);             /* buffer length */

              /* Foreach channel... */
              for (ch = 0; ch < number_of_channels; ++ch) {
                g_snprintf(temp_buff, MAX_LABEL_SIZE, "Channel[%u]", ch);
                old_offset = off;
                if (tree) {
                  ti_channel = proto_tree_add_text(rtps_parameter_tree,
                    tvb,
                    off,
                    0,
                    "%s",
                    temp_buff);
                  channel_tree = proto_item_add_subtree(ti_channel, ett_rtps_locator_filter_channel);
                }
                off = rtps_util_add_locator_list(channel_tree,
                  tvb,
                  off,
                  temp_buff,
                  little_endian);
                /* Filter expression */
                off = rtps_util_add_string(channel_tree,
                  tvb,
                  off,
                  -1,                    /* hf_item not set */
                  little_endian,
                  "filterExpression",    /* label */
                  NULL,                  /* buffer not set */
                  0);                    /* buffer length */
                /* Now we know the length of the channel data, set the length */
                if (ti_channel) {
                  proto_item_set_len(ti_channel, (off - old_offset));
                }
              } /* End of for each channel */
              break;
            } /* End of case PID_LOCATOR_FILTER_LIST */

          } /* End of switch for parameters for vendor RTI */
        } /* End of branch vendor RTI */
        else if (vendor_id == RTPS_VENDOR_TOC) {
          switch(parameter) {
            /* 0...2...........7...............15.............23...............31
             * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
             * | PID_TYPECODE                  |            length             |
             * +---------------+---------------+---------------+---------------+
             * |                                                               |
             * +                    Type code description                      +
             * |                                                               |
             * +---------------+---------------+---------------+---------------+
             */
            case PID_TYPECODE:
              rtps_util_add_typecode(rtps_parameter_tree,
                        tvb,
                        offset,
                        little_endian,
                        0,      /* indent level */
                        0,      /* isPointer */
                        -1,     /* bitfield */
                        0,      /* isKey */
                        offset,
                        NULL,   /* name */
                        0,      /* not a seq field */
                        NULL,   /* not an array */
                        0);     /* ndds 4.0 hack: init to false */
              break;
            default:
              break;
          } /* End of switch for parameters for vendor TOC */
        } /* End of branch vendor TOC */

        /* Put here other branches if you are planning to dissect parameters
         * ID from different vendors.
         */

        else {
          if (param_length > 0) {
            proto_tree_add_text(rtps_parameter_tree,
                        tvb,
                        offset,
                        param_length,
                        "parameterData");
          }
        }
    } /* End main parameter switch */

    if (buffer[0]) {
      proto_item_append_text(ti, ": %s", buffer);
      buffer[0] = '\0';
    }
    offset += param_length;

  } /* for all the parameters */
  g_assert_not_reached();
}
#undef ENSURE_LENGTH




/* *********************************************************************** */
/* *                                 P A D                               * */
/* *********************************************************************** */
static void dissect_PAD(tvbuff_t *tvb,
                gint offset,
                guint8 flags,
                gboolean little_endian,
                int octets_to_next_header,
                proto_tree *tree,
                char * info_summary_text,
                guint16 G_GNUC_UNUSED vendor_id) {
  /* 0...2...........7...............15.............23...............31
   * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   * |   PAD         |X|X|X|X|X|X|X|E|      octetsToNextHeader       |
   * +---------------+---------------+---------------+---------------+
   */
  if (tree) {
    rtps_util_decode_flags(tree, tvb, offset + 1, flags, PAD_FLAGS);

    if (octets_to_next_header != 0) {
      proto_tree_add_uint_format(tree,
                          hf_rtps_sm_octets_to_next_header,
                          tvb,
                          offset + 2,
                          2,
                          octets_to_next_header,
                          "octetsToNextHeader: %u (Error: should be ZERO)",
                          octets_to_next_header);
      return;
    }

    proto_tree_add_item(tree,
                          hf_rtps_sm_octets_to_next_header,
                          tvb,
                          offset + 2,
                          2,
                          little_endian);
  }
  info_summary_append(info_summary_text, SUBMESSAGE_PAD, NULL);
}





/* *********************************************************************** */
/* *                               D A T A                               * */
/* *********************************************************************** */
static void dissect_DATA(tvbuff_t *tvb,
                gint offset,
                guint8 flags,
                gboolean little_endian,
                int octets_to_next_header,
                proto_tree *tree,
                char * info_summary_text,
                guint16 vendor_id) {
  /*
   *
   * 0...2...........7...............15.............23...............31
   * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   * |   DATA        |X|X|X|I|H|D|Q|E|      octetsToNextHeader       |
   * +---------------+---------------+---------------+---------------+
   * | EntityId readerEntityId                                       |
   * +---------------+---------------+---------------+---------------+
   * | EntityId writerEntityId                                       |
   * +---------------+---------------+---------------+---------------+
   * |                                                               |
   * + SequenceNumber writerSeqNum                                   +
   * |                                                               |
   * +---------------+---------------+---------------+---------------+
   * |                                                               |
   * +                                                               +
   * | KeyHashPrefix  keyHashPrefix [only if H==1]                   |
   * +                                                               +
   * |                                                               |
   * +---------------+---------------+---------------+---------------+
   * | KeyHashSuffix  keyHashSuffix                                  |
   * +---------------+---------------+---------------+---------------+
   * | StatusInfo statusInfo [only if I==1]                          |
   * +---------------+---------------+---------------+---------------+
   * |                                                               |
   * ~ ParameterList inlineQos [only if Q==1]                        ~
   * |                                                               |
   * +---------------+---------------+---------------+---------------+
   * |                                                               |
   * ~ SerializedData serializedData [only if D==1]                  ~
   * |                                                               |
   * +---------------+---------------+---------------+---------------+
   */
  int min_len;
  gint old_offset = offset;
  guint32 wid;                  /* Writer EntityID */
  guint32 status_info = 0xffffffff;

  rtps_util_decode_flags(tree, tvb, offset + 1, flags, DATA_FLAGS);


  /* Calculates the minimum length for this submessage */
  min_len = 20;
  if ((flags & FLAG_DATA_Q) != 0) min_len += 4;
  if ((flags & FLAG_DATA_D) != 0) min_len += 4;
  if ((flags & FLAG_DATA_H) != 0) min_len += 12;

  if (octets_to_next_header < min_len) {
    if (tree) proto_tree_add_uint_format(tree,
                        hf_rtps_sm_octets_to_next_header,
                        tvb,
                        offset+2,
                        2,
                        octets_to_next_header,
                        "octetsToNextHeader: %u (Error: should be >= %u)",
                        octets_to_next_header,
                        min_len);
    return;
  }

  /* Skip decoding the entire packet if (tree == NULL)
   * Note that we still need to decode the statusInfo and the writer ID
   */
  if (tree == NULL) {
    offset += 8;    /* Skip to writer entity ID */
    wid = NEXT_guint32(tvb, offset, little_endian);
    offset += 12;   /* Skip to keyHashPrefix */
    if ((flags & FLAG_DATA_H) != 0) {
      offset += 12;
    }
    offset += 4;  /* GUID Entity ID */
    if ((flags & FLAG_DATA_I) != 0) {
      status_info = NEXT_guint32(tvb, offset, little_endian);
    }
    info_summary_append_ex(info_summary_text, SUBMESSAGE_DATA, wid, status_info);
    return;
  }

  if (tree) proto_tree_add_item(tree,
                        hf_rtps_sm_octets_to_next_header,
                        tvb,
                        offset + 2,
                        2,
                        little_endian);
  offset += 4;


  /* readerEntityId */
  rtps_util_add_entity_id(tree,
                        tvb,
                        offset,
                        hf_rtps_sm_rdentity_id,
                        hf_rtps_sm_rdentity_id_key,
                        hf_rtps_sm_rdentity_id_kind,
                        ett_rtps_rdentity,
                        "readerEntityId",
                        NULL);
  offset += 4;

  /* writerEntityId */
  rtps_util_add_entity_id(tree,
                        tvb,
                        offset,
                        hf_rtps_sm_wrentity_id,
                        hf_rtps_sm_wrentity_id_key,
                        hf_rtps_sm_wrentity_id_kind,
                        ett_rtps_wrentity,
                        "writerEntityId",
                        &wid);
  offset += 4;


  /* Sequence number */
  rtps_util_add_seq_number(tree,
                        tvb,
                        offset,
                        little_endian,
                        "writerSeqNumber");
  offset += 8;

  /* If flag H is defined, read the GUID Prefix */
  if ((flags & FLAG_DATA_H) != 0) {
    rtps_util_add_guid_prefix(tree,
                        tvb,
                        offset,
                        hf_rtps_sm_guid_prefix,
                        hf_rtps_sm_host_id,
                        hf_rtps_sm_app_id,
                        hf_rtps_sm_counter,
                        "keyHashPrefix",
                        NULL,
                        0);

    offset += 12;
  } else {
    /* Flag H not set, use hostId, appId from the packet header */
  }

  /* Complete the GUID by reading the Object ID */
  rtps_util_add_entity_id(tree,
                        tvb,
                        offset,
                        hf_rtps_sm_entity_id,
                        hf_rtps_sm_entity_id_key,
                        hf_rtps_sm_entity_id_kind,
                        ett_rtps_entity,
                        "keyHashSuffix",
                        NULL);
  offset += 4;

  if ((flags & FLAG_DATA_I) != 0) {
    status_info = rtps_util_add_long(tree,
                        tvb,
                        offset,
                        -1,
                        little_endian,
                        1,      /* is_hex */
                        0,      /* is_signed */
                        "statusInfo",
                        NULL,
                        0);
    offset += 4;
  }

  /* InlineQos */
  if ((flags & FLAG_DATA_Q) != 0) {
    offset = dissect_parameter_sequence(tree,
                        tvb,
                        offset,
                        little_endian,
                        octets_to_next_header - (offset - old_offset) + 4,
                        "inlineQos",
                        NULL,
                        vendor_id);
  }

  /* SerializedData */
  if ((flags & FLAG_DATA_D) != 0) {
    dissect_serialized_data(tree,
                        tvb,
                        offset,
                        octets_to_next_header - (offset - old_offset) + 4,
                        "serializedData",
                        vendor_id);
  }
  info_summary_append_ex(info_summary_text, SUBMESSAGE_DATA, wid, status_info);
}


/* *********************************************************************** */
/* *                          D A T A _ F R A G                          * */
/* *********************************************************************** */
static void dissect_DATA_FRAG(tvbuff_t *tvb,
                gint offset,
                guint8 flags,
                gboolean little_endian,
                int octets_to_next_header,
                proto_tree *tree,
                char *info_summary_text,
                guint16 vendor_id) {
  /*
   * 0...2...........7...............15.............23...............31
   * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   * | DATA_FRAG     |X|X|X|X|X|H|Q|E|      octetsToNextHeader       |
   * +---------------+---------------+---------------+---------------+
   * | EntityId readerEntityId                                       |
   * +---------------+---------------+---------------+---------------+
   * | EntityId writerEntityId                                       |
   * +---------------+---------------+---------------+---------------+
   * |                                                               |
   * + SequenceNumber writerSeqNum                                   +
   * |                                                               |
   * +---------------+---------------+---------------+---------------+
   * |                                                               |
   * +                                                               +
   * | KeyHashPrefix  keyHashPrefix [only if H==1]                   |
   * +                                                               +
   * |                                                               |
   * +---------------+---------------+---------------+---------------+
   * | KeyHashSuffix  keyHashSuffix                                  |
   * +---------------+---------------+---------------+---------------+
   * | FragmentNumber fragmentStartingNum                            |
   * +---------------+---------------+---------------+---------------+
   * | ushort fragmentsInSubmessage  | ushort fragmentSize           |
   * +---------------+---------------+---------------+---------------+
   * | unsigned long sampleSize                                      |
   * +---------------+---------------+---------------+---------------+
   * |                                                               |
   * ~ ParameterList inlineQos [only if Q==1]                        ~
   * |                                                               |
   * +---------------+---------------+---------------+---------------+
   * |                                                               |
   * ~ SerializedData serializedData                                 ~
   * |                                                               |
   * +---------------+---------------+---------------+---------------+
   */

  int  min_len;
  gint old_offset = offset;
  rtps_util_decode_flags(tree, tvb, offset + 1, flags, NOKEY_DATA_FRAG_FLAGS);


  /* Calculates the minimum length for this submessage */
  min_len = 32;
  if ((flags & FLAG_DATA_FRAG_Q) != 0) min_len += 4;
  if ((flags & FLAG_DATA_FRAG_H) != 0) min_len += 12;

  if (octets_to_next_header < min_len) {
    proto_tree_add_uint_format(tree,
                        hf_rtps_sm_octets_to_next_header,
                        tvb,
                        offset+2,
                        2,
                        octets_to_next_header,
                        "octetsToNextHeader: %u (Error: should be >= %u)",
                        octets_to_next_header,
                        min_len);
    return;
  }

  /* Skip decoding the entire packet if (tree == NULL)
   * Note that we still need to decode the statusInfo and the writer ID
   */
  if (tree == NULL) {
    info_summary_append(info_summary_text, SUBMESSAGE_DATA_FRAG, NULL);
    return;
  }

  proto_tree_add_item(tree,
                        hf_rtps_sm_octets_to_next_header,
                        tvb,
                        offset + 2,
                        2,
                        little_endian);
  offset += 4;

  /* readerEntityId */
  rtps_util_add_entity_id(tree,
                        tvb,
                        offset,
                        hf_rtps_sm_rdentity_id,
                        hf_rtps_sm_rdentity_id_key,
                        hf_rtps_sm_rdentity_id_kind,
                        ett_rtps_rdentity,
                        "readerEntityId",
                        NULL);
  offset += 4;

  /* writerEntityId */
  rtps_util_add_entity_id(tree,
                        tvb,
                        offset,
                        hf_rtps_sm_wrentity_id,
                        hf_rtps_sm_wrentity_id_key,
                        hf_rtps_sm_wrentity_id_kind,
                        ett_rtps_wrentity,
                        "writerEntityId",
                        NULL);
  offset += 4;

  /* Sequence number */
  rtps_util_add_seq_number(tree,
                        tvb,
                        offset,
                        little_endian,
                        "writerSeqNumber");
  offset += 8;

  /* If flag H is defined, read the GUID Prefix */
  if ((flags & FLAG_DATA_H) != 0) {
    rtps_util_add_guid_prefix(tree,
                        tvb,
                        offset,
                        hf_rtps_sm_guid_prefix,
                        hf_rtps_sm_host_id,
                        hf_rtps_sm_app_id,
                        hf_rtps_sm_counter,
                        "keyHashPrefix",
                        NULL,
                        0);

    offset += 12;
  } else {
    /* Flag H not set, use hostId, appId from the packet header */
  }

  /* Complete the GUID by reading the Object ID */
  rtps_util_add_entity_id(tree,
                        tvb,
                        offset,
                        hf_rtps_sm_entity_id,
                        hf_rtps_sm_entity_id_key,
                        hf_rtps_sm_entity_id_kind,
                        ett_rtps_entity,
                        "keyHashSuffix",
                        NULL);
  offset += 4;


  /* Fragment number */
  rtps_util_add_long(tree,
                        tvb,
                        offset,
                        -1,
                        little_endian,
                        0,      /* is_hex */
                        0,      /* is_signed */
                        "fragmentStartingNum",
                        NULL,
                        0);
  offset += 4;

  /* Fragments in submessage */
  rtps_util_add_short(tree,
                        tvb,
                        offset,
                        -1,
                        little_endian,
                        0,      /* is_hex */
                        0,      /* is_signed */
                        "fragmentsInSubmessage",
                        NULL,
                        0);
  offset += 2;

  /* Fragment size */
  rtps_util_add_short(tree,
                        tvb,
                        offset,
                        -1,
                        little_endian,
                        0,      /* is_hex */
                        0,      /* is_signed */
                        "fragmentSize",
                        NULL,
                        0);
  offset += 2;

  /* sampleSize */
  rtps_util_add_long(tree,
                        tvb,
                        offset,
                        -1,
                        little_endian,
                        0,      /* is_hex */
                        0,      /* is_signed */
                        "sampleSize",
                        NULL,
                        0);
  offset += 4;

  /* InlineQos */
  if ((flags & FLAG_DATA_Q) != 0) {
    offset = dissect_parameter_sequence(tree,
                        tvb,
                        offset,
                        little_endian,
                        octets_to_next_header - (offset - old_offset) + 4,
                        "inlineQos",
                        NULL,
                        vendor_id);
  }

  /* SerializedData */
  if ((flags & FLAG_DATA_D) != 0) {
    dissect_serialized_data(tree,
                        tvb,
                        offset,
                        octets_to_next_header - (offset - old_offset) + 4,
                        "serializedData",
                        vendor_id);
  }
  info_summary_append(info_summary_text, SUBMESSAGE_DATA_FRAG, NULL);
}



/* *********************************************************************** */
/* *                        N O K E Y _ D A T A                          * */
/* *********************************************************************** */
static void dissect_NOKEY_DATA(tvbuff_t *tvb,
                gint offset,
                guint8 flags,
                gboolean little_endian,
                int octets_to_next_header,
                proto_tree *tree,
                char * info_summary_text,
                guint16 vendor_id) {
  /*
   * RTPS 2.0:
   * 0...2...........7...............15.............23...............31
   * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   * | NOKEY_DATA    |X|X|X|X|X|D|Q|E|      octetsToNextHeader       |
   * +---------------+---------------+---------------+---------------+
   * | EntityId readerEntityId                                       |
   * +---------------+---------------+---------------+---------------+
   * | EntityId writerEntityId                                       |
   * +---------------+---------------+---------------+---------------+
   * |                                                               |
   * + SequenceNumber writerSeqNum                                   +
   * |                                                               |
   * +---------------+---------------+---------------+---------------+
   * |                                                               |
   * ~ ParameterList inlineQos [only if Q==1]                        ~
   * |                                                               |
   * +---------------+---------------+---------------+---------------+
   * |                                                               |
   * ~ SerializedData serializedData [only if D==1]                  ~
   * |                                                               |
   * +---------------+---------------+---------------+---------------+
   */

  int  min_len;
  gint old_offset = offset;
  rtps_util_decode_flags(tree, tvb, offset + 1, flags, NOKEY_DATA_FLAGS);


  /* Calculates the minimum length for this submessage */
  min_len = 16;
  if ((flags & FLAG_NOKEY_DATA_Q) != 0) min_len += 4;

  if (octets_to_next_header < min_len) {
    proto_tree_add_uint_format(tree,
                        hf_rtps_sm_octets_to_next_header,
                        tvb,
                        offset+2,
                        2,
                        octets_to_next_header,
                        "octetsToNextHeader: %u (Error: should be >= %u)",
                        octets_to_next_header,
                        min_len);
    return;
  }

  /* Skip decoding the entire packet if (tree == NULL)
   * Note that we still need to decode the statusInfo and the writer ID
   */
  if (tree == NULL) {
    info_summary_append(info_summary_text, SUBMESSAGE_NOKEY_DATA, NULL);
    return;
  }

  proto_tree_add_item(tree,
                        hf_rtps_sm_octets_to_next_header,
                        tvb,
                        offset + 2,
                        2,
                        little_endian);
  offset += 4;

  /* readerEntityId */
  rtps_util_add_entity_id(tree,
                        tvb,
                        offset,
                        hf_rtps_sm_rdentity_id,
                        hf_rtps_sm_rdentity_id_key,
                        hf_rtps_sm_rdentity_id_kind,
                        ett_rtps_rdentity,
                        "readerEntityId",
                        NULL);
  offset += 4;

  /* writerEntityId */
  rtps_util_add_entity_id(tree,
                        tvb,
                        offset,
                        hf_rtps_sm_wrentity_id,
                        hf_rtps_sm_wrentity_id_key,
                        hf_rtps_sm_wrentity_id_kind,
                        ett_rtps_wrentity,
                        "writerEntityId",
                        NULL);
  offset += 4;

  /* Sequence number */
  rtps_util_add_seq_number(tree,
                        tvb,
                        offset,
                        little_endian,
                        "writerSeqNumber");
  offset += 8;

  /* InlineQos */
  if ((flags & FLAG_DATA_Q) != 0) {
    offset = dissect_parameter_sequence(tree,
                        tvb,
                        offset,
                        little_endian,
                        octets_to_next_header - (offset - old_offset) + 4,
                        "inlineQos",
                        NULL,
                        vendor_id);
  }

  /* SerializedData */
  if ((flags & FLAG_DATA_D) != 0) {
    dissect_serialized_data(tree,
                        tvb,
                        offset,
                        octets_to_next_header - (offset - old_offset) + 4,
                        "serializedData",
                        vendor_id);
  }
  info_summary_append(info_summary_text, SUBMESSAGE_NOKEY_DATA, NULL);
}


/* *********************************************************************** */
/* *                    N O K E Y _ D A T A _ F R A G                    * */
/* *********************************************************************** */
static void dissect_NOKEY_DATA_FRAG(tvbuff_t *tvb,
                gint offset,
                guint8 flags,
                gboolean little_endian,
                int octets_to_next_header,
                proto_tree *tree,
                char * info_summary_text,
                guint16 vendor_id) {
  /*
   * 0...2...........7...............15.............23...............31
   * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   * |NOKEY_DATA_FRAG|X|X|X|X|X|X|Q|E|      octetsToNextHeader       |
   * +---------------+---------------+---------------+---------------+
   * | EntityId readerEntityId                                       |
   * +---------------+---------------+---------------+---------------+
   * | EntityId writerEntityId                                       |
   * +---------------+---------------+---------------+---------------+
   * |                                                               |
   * + SequenceNumber writerSeqNum                                   +
   * |                                                               |
   * +---------------+---------------+---------------+---------------+
   * | FragmentNumber fragmentStartingNum                            |
   * +---------------+---------------+---------------+---------------+
   * | ushort fragmentsInSubmessage  | ushort fragmentSize           |
   * +---------------+---------------+---------------+---------------+
   * | unsigned long sampleSize                                      |
   * +---------------+---------------+---------------+---------------+
   * |                                                               |
   * ~ ParameterList inlineQos [only if Q==1]                        ~
   * |                                                               |
   * +---------------+---------------+---------------+---------------+
   * |                                                               |
   * ~ SerializedData serializedData                                 ~
   * |                                                               |
   * +---------------+---------------+---------------+---------------+
   */

  int  min_len;
  gint old_offset = offset;
  rtps_util_decode_flags(tree, tvb, offset + 1, flags, NOKEY_DATA_FRAG_FLAGS);


  /* Calculates the minimum length for this submessage */
  min_len = 28;
  if ((flags & FLAG_NOKEY_DATA_Q) != 0) min_len += 4;

  if (octets_to_next_header < min_len) {
    proto_tree_add_uint_format(tree,
                        hf_rtps_sm_octets_to_next_header,
                        tvb,
                        offset+2,
                        2,
                        octets_to_next_header,
                        "octetsToNextHeader: %u (Error: should be >= %u)",
                        octets_to_next_header,
                        min_len);
    return;
  }

  /* Skip decoding the entire packet if (tree == NULL)
   * Note that we still need to decode the statusInfo and the writer ID
   */
  if (tree == NULL) {
    info_summary_append(info_summary_text, SUBMESSAGE_NOKEY_DATA_FRAG, NULL);
    return;
  }

  proto_tree_add_item(tree,
                        hf_rtps_sm_octets_to_next_header,
                        tvb,
                        offset + 2,
                        2,
                        little_endian);
  offset += 4;

  /* readerEntityId */
  rtps_util_add_entity_id(tree,
                        tvb,
                        offset,
                        hf_rtps_sm_rdentity_id,
                        hf_rtps_sm_rdentity_id_key,
                        hf_rtps_sm_rdentity_id_kind,
                        ett_rtps_rdentity,
                        "readerEntityId",
                        NULL);
  offset += 4;

  /* writerEntityId */
  rtps_util_add_entity_id(tree,
                        tvb,
                        offset,
                        hf_rtps_sm_wrentity_id,
                        hf_rtps_sm_wrentity_id_key,
                        hf_rtps_sm_wrentity_id_kind,
                        ett_rtps_wrentity,
                        "writerEntityId",
                        NULL);
  offset += 4;

  /* Sequence number */
  rtps_util_add_seq_number(tree,
                        tvb,
                        offset,
                        little_endian,
                        "writerSeqNumber");
  offset += 8;

  /* Fragment number */
  rtps_util_add_long(tree,
                        tvb,
                        offset,
                        -1,
                        little_endian,
                        0,      /* is_hex */
                        0,      /* is_signed */
                        "fragmentStartingNum",
                        NULL,
                        0);
  offset += 4;

  /* Fragments in submessage */
  rtps_util_add_short(tree,
                        tvb,
                        offset,
                        -1,
                        little_endian,
                        0,      /* is_hex */
                        0,      /* is_signed */
                        "fragmentsInSubmessage",
                        NULL,
                        0);
  offset += 2;

  /* Fragment size */
  rtps_util_add_short(tree,
                        tvb,
                        offset,
                        -1,
                        little_endian,
                        0,      /* is_hex */
                        0,      /* is_signed */
                        "fragmentSize",
                        NULL,
                        0);
  offset += 2;

  /* InlineQos */
  if ((flags & FLAG_DATA_Q) != 0) {
    offset = dissect_parameter_sequence(tree,
                        tvb,
                        offset,
                        little_endian,
                        octets_to_next_header - (offset - old_offset) + 4,
                        "inlineQos",
                        NULL,
                        vendor_id);
  }

  /* SerializedData */
  if ((flags & FLAG_DATA_D) != 0) {
    dissect_serialized_data(tree,
                        tvb,
                        offset,
                        octets_to_next_header - (offset - old_offset) + 4,
                        "serializedData",
                        vendor_id);
  }
  info_summary_append(info_summary_text, SUBMESSAGE_NOKEY_DATA_FRAG, NULL);
}



/* *********************************************************************** */
/* *                            A C K N A C K                            * */
/* *********************************************************************** */
static void dissect_ACKNACK(tvbuff_t *tvb,
                gint offset,
                guint8 flags,
                gboolean little_endian,
                int octets_to_next_header,
                proto_tree *tree,
                char * info_summary_text,
                guint16 G_GNUC_UNUSED vendor_id ) {
  /*
   * 0...2...........7...............15.............23...............31
   * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   * |   ACKNACK     |X|X|X|X|X|X|F|E|      octetsToNextHeader       |
   * +---------------+---------------+---------------+---------------+
   * | EntityId readerEntityId                                       |
   * +---------------+---------------+---------------+---------------+
   * | EntityId writerEntityId                                       |
   * +---------------+---------------+---------------+---------------+
   * |                                                               |
   * + SequenceNumberSet readerSNState                               +
   * |                                                               |
   * +---------------+---------------+---------------+---------------+
   * | Counter count                                                 |
   * +---------------+---------------+---------------+---------------+
   */
  gint original_offset; /* Offset to the readerEntityId */

  rtps_util_decode_flags(tree, tvb, offset + 1, flags, ACKNACK_FLAGS);

  if (octets_to_next_header < 20) {
    proto_tree_add_uint_format(tree,
                        hf_rtps_sm_octets_to_next_header,
                        tvb,
                        offset + 2,
                        2,
                        octets_to_next_header,
                        "octetsToNextHeader: %u (Error: should be >= 20)",
                        octets_to_next_header);
    return;
  }

  /* Skip decoding the entire packet if (tree == NULL)
   * Note that we still need to decode the statusInfo and the writer ID
   */
  if (tree == NULL) {
    info_summary_append(info_summary_text, SUBMESSAGE_ACKNACK, NULL);
    return;
  }

  proto_tree_add_item(tree,
                        hf_rtps_sm_octets_to_next_header,
                        tvb,
                        offset + 2,
                        2,
                        little_endian);
  offset += 4;
  original_offset = offset;

  /* readerEntityId */
  rtps_util_add_entity_id(tree,
                        tvb,
                        offset,
                        hf_rtps_sm_rdentity_id,
                        hf_rtps_sm_rdentity_id_key,
                        hf_rtps_sm_rdentity_id_kind,
                        ett_rtps_rdentity,
                        "readerEntityId",
                        NULL);
  offset += 4;

  /* writerEntityId */
  rtps_util_add_entity_id(tree,
                        tvb,
                        offset,
                        hf_rtps_sm_wrentity_id,
                        hf_rtps_sm_wrentity_id_key,
                        hf_rtps_sm_wrentity_id_kind,
                        ett_rtps_wrentity,
                        "writerEntityId",
                        NULL);
  offset += 4;

  /* Bitmap */
  offset = rtps_util_add_bitmap(tree,
                        tvb,
                        offset,
                        little_endian,
                        "readerSNState");


  /* RTPS 1.0 didn't have count: make sure we don't decode it wrong
   * in this case
   */
  if (offset + 4 == original_offset + octets_to_next_header) {
    /* Count is present */
    rtps_util_add_long(tree,
                  tvb,
                  offset,
                  -1,
                  little_endian,
                  FALSE,        /* Is Hex ? */
                  TRUE,         /* Is Signed ? */
                  "counter",    /* No Label, use the protocol item ID */
                  NULL,
                  0);
  } else if (offset < original_offset + octets_to_next_header) {
    /* In this case there must be something wrong in the bitmap: there
     * are some extra bytes that we don't know how to decode
     */
    proto_tree_add_text(tree,
                        tvb,
                        offset,
                        octets_to_next_header - offset,
                        "Packet malformed: don't know how to decode those "
                        "extra bytes: %d",
                        octets_to_next_header - offset);
  } else if (offset > original_offset + octets_to_next_header) {
    /* Decoding the bitmap went over the end of this submessage.
     * Enter an item in the protocol tree that spans over the entire
     * submessage.
     */
    proto_tree_add_text(tree,
                        tvb,
                        original_offset,
                        octets_to_next_header + original_offset,
                        "Packet malformed: not enough bytes to decode");
  }
  info_summary_append(info_summary_text, SUBMESSAGE_ACKNACK, NULL);
}


/* *********************************************************************** */
/* *                          N A C K _ F R A G                          * */
/* *********************************************************************** */
static void dissect_NACK_FRAG(tvbuff_t *tvb,
                gint offset,
                guint8 flags,
                gboolean little_endian,
                int octets_to_next_header,
                proto_tree *tree,
                char * info_summary_text,
                guint16 G_GNUC_UNUSED vendor_id ) {
  /*
   * 0...2...........7...............15.............23...............31
   * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   * |   NACK_FRAG   |X|X|X|X|X|X|X|E|      octetsToNextHeader       |
   * +---------------+---------------+---------------+---------------+
   * | EntityId readerEntityId                                       |
   * +---------------+---------------+---------------+---------------+
   * | EntityId writerEntityId                                       |
   * +---------------+---------------+---------------+---------------+
   * |                                                               |
   * + SequenceNumberSet writerSN                                    +
   * |                                                               |
   * +---------------+---------------+---------------+---------------+
   * |                                                               |
   * ~ FragmentNumberSet fragmentNumberState                         +
   * |                                                               |
   * +---------------+---------------+---------------+---------------+
   * | Counter count                                                 |
   * +---------------+---------------+---------------+---------------+
   */
  rtps_util_decode_flags(tree, tvb, offset + 1, flags, NACK_FRAG_FLAGS);

  if (octets_to_next_header < 24) {
    proto_tree_add_uint_format(tree,
                        hf_rtps_sm_octets_to_next_header,
                        tvb,
                        offset + 2,
                        2,
                        octets_to_next_header,
                        "octetsToNextHeader: %u (Error: should be >= 24)",
                        octets_to_next_header);
    return;
  }

  /* Skip decoding the entire packet if (tree == NULL)
   * Note that we still need to decode the statusInfo and the writer ID
   */
  if (tree == NULL) {
    info_summary_append(info_summary_text, SUBMESSAGE_NACK_FRAG, NULL);
    return;
  }


  proto_tree_add_item(tree,
                        hf_rtps_sm_octets_to_next_header,
                        tvb,
                        offset + 2,
                        2,
                        little_endian);
  offset += 4;

  /* readerEntityId */
  rtps_util_add_entity_id(tree,
                        tvb,
                        offset,
                        hf_rtps_sm_rdentity_id,
                        hf_rtps_sm_rdentity_id_key,
                        hf_rtps_sm_rdentity_id_kind,
                        ett_rtps_rdentity,
                        "readerEntityId",
                        NULL);
  offset += 4;

  /* writerEntityId */
  rtps_util_add_entity_id(tree,
                        tvb,
                        offset,
                        hf_rtps_sm_wrentity_id,
                        hf_rtps_sm_wrentity_id_key,
                        hf_rtps_sm_wrentity_id_kind,
                        ett_rtps_wrentity,
                        "writerEntityId",
                        NULL);
  offset += 4;

  /* Writer sequence number */
  rtps_util_add_seq_number(tree,
                        tvb,
                        offset,
                        little_endian,
                        "writerSN");
  offset += 8;

  /* FragmentNumberSet */
  offset = rtps_util_add_fragment_number_set(tree,
                        tvb,
                        offset,
                        little_endian,
                        "fragmentNumberState",
                        octets_to_next_header - 20);
  info_summary_append(info_summary_text, SUBMESSAGE_NACK_FRAG, NULL);

  if (offset == -1) {
    return;
  }
  /* Count */
  rtps_util_add_long(tree,
                  tvb,
                  offset,
                  -1,
                  little_endian,
                  FALSE,        /* Is Hex ? */
                  TRUE,         /* Is Signed ? */
                  "count",      /* No Label, use the protocol item ID */
                  NULL,
                  0);
}



/* *********************************************************************** */
/* *                           H E A R T B E A T                         * */
/* *********************************************************************** */
static void dissect_HEARTBEAT(tvbuff_t *tvb,
                gint offset,
                guint8 flags,
                gboolean little_endian,
                int octets_to_next_header,
                proto_tree *tree,
                char * info_summary_text,
                guint16 G_GNUC_UNUSED vendor_id) {
  /*
   * 0...2...........7...............15.............23...............31
   * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   * |   HEARTBEAT   |X|X|X|X|X|L|F|E|      octetsToNextHeader       |
   * +---------------+---------------+---------------+---------------+
   * | EntityId readerEntityId                                       |
   * +---------------+---------------+---------------+---------------+
   * | EntityId writerEntityId                                       |
   * +---------------+---------------+---------------+---------------+
   * |                                                               |
   * + SequenceNumber firstSeqNumber                                 +
   * |                                                               |
   * +---------------+---------------+---------------+---------------+
   * |                                                               |
   * + SequenceNumber lastSeqNumber                                  +
   * |                                                               |
   * +---------------+---------------+---------------+---------------+
   * | Counter count                                                 |
   * +---------------+---------------+---------------+---------------+
   */

  rtps_util_decode_flags(tree, tvb, offset + 1, flags, HEARTBEAT_FLAGS);


  if (octets_to_next_header < 28) {
    proto_tree_add_uint_format(tree,
                        hf_rtps_sm_octets_to_next_header,
                        tvb,
                        offset+2,
                        2,
                        octets_to_next_header,
                        "octetsToNextHeader: %u (Error: should be >= 28)",
                        octets_to_next_header);
    return;
  }

  /* Skip decoding the entire packet if (tree == NULL)
   * Note that we still need to decode the statusInfo and the writer ID
   */
  if (tree == NULL) {
    info_summary_append(info_summary_text, SUBMESSAGE_HEARTBEAT, NULL);
    return;
  }

  proto_tree_add_item(tree,
                        hf_rtps_sm_octets_to_next_header,
                        tvb,
                        offset + 2,
                        2,
                        little_endian);
  offset += 4;

  /* readerEntityId */
  rtps_util_add_entity_id(tree,
                        tvb,
                        offset,
                        hf_rtps_sm_rdentity_id,
                        hf_rtps_sm_rdentity_id_key,
                        hf_rtps_sm_rdentity_id_kind,
                        ett_rtps_rdentity,
                        "readerEntityId",
                        NULL);
  offset += 4;

  /* writerEntityId */
  rtps_util_add_entity_id(tree,
                        tvb,
                        offset,
                        hf_rtps_sm_wrentity_id,
                        hf_rtps_sm_wrentity_id_key,
                        hf_rtps_sm_wrentity_id_kind,
                        ett_rtps_wrentity,
                        "writerEntityId",
                        NULL);
  offset += 4;

  /* First available Sequence Number */
  rtps_util_add_seq_number(tree,
                        tvb,
                        offset,
                        little_endian,
                        "firstSeqNumber");
  offset += 8;

  /* Last Sequence Number */
  rtps_util_add_seq_number(tree,
                        tvb,
                        offset,
                        little_endian,
                        "lastSeqNumber");
  offset += 8;

  /* Counter */
  rtps_util_add_long(tree,
                        tvb,
                        offset,
                        -1,
                        little_endian,
                        0,      /* is_hex */
                        0,      /* is_signed */
                        "count",
                        NULL,
                        0);
  info_summary_append(info_summary_text, SUBMESSAGE_HEARTBEAT, NULL);
}


/* *********************************************************************** */
/* *                 H E A R T B E A T _ B A T C H                       * */
/* *********************************************************************** */
static void dissect_HEARTBEAT_BATCH(tvbuff_t *tvb,
                gint offset,
                guint8 flags,
                gboolean little_endian,
                int octets_to_next_header,
                proto_tree *tree,
                char * info_summary_text,
                guint16 G_GNUC_UNUSED vendor_id) {


  /*
   * 0...2...........7...............15.............23...............31
   * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   * |HEARTBEAT_BATCH|X|X|X|X|X|L|F|E|      octetsToNextHeader       |
   * +---------------+---------------+---------------+---------------+
   * | EntityId readerId                                             |
   * +---------------+---------------+---------------+---------------+
   * | EntityId writerId                                             |
   * +---------------+---------------+---------------+---------------+
   * |                                                               |
   * + SequenceNumber firstBatchSN                                   +
   * |                                                               |
   * +---------------+---------------+---------------+---------------+
   * |                                                               |
   * + SequenceNumber lastBatchSN                                    +
   * |                                                               |
   * +---------------+---------------+---------------+---------------+
   * |                                                               |
   * + SequenceNumber firstSN                                        +
   * |                                                               |
   * +---------------+---------------+---------------+---------------+
   * |                                                               |
   * + SequenceNumber lastSN                                         +
   * |                                                               |
   * +---------------+---------------+---------------+---------------+
   * | Count count                                                   |
   * +---------------+---------------+---------------+---------------+
   */

  rtps_util_decode_flags(tree, tvb, offset + 1, flags, HEARTBEAT_BATCH_FLAGS);


  if (octets_to_next_header < 36) {
    proto_tree_add_uint_format(tree,
                        hf_rtps_sm_octets_to_next_header,
                        tvb,
                        offset+2,
                        2,
                        octets_to_next_header,
                        "octetsToNextHeader: %u (Error: should be >= 36)",
                        octets_to_next_header);
    return;
  }

  /* Skip decoding the entire packet if (tree == NULL)
   * Note that we still need to decode the statusInfo and the writer ID
   */
  if (tree == NULL) {
    info_summary_append(info_summary_text, SUBMESSAGE_HEARTBEAT, NULL);
    return;
  }
  proto_tree_add_item(tree,
                        hf_rtps_sm_octets_to_next_header,
                        tvb,
                        offset + 2,
                        2,
                        little_endian);
  offset += 4;

  /* readerEntityId */
  rtps_util_add_entity_id(tree,
                        tvb,
                        offset,
                        hf_rtps_sm_rdentity_id,
                        hf_rtps_sm_rdentity_id_key,
                        hf_rtps_sm_rdentity_id_kind,
                        ett_rtps_rdentity,
                        "readerEntityId",
                        NULL);
  offset += 4;

  /* writerEntityId */
  rtps_util_add_entity_id(tree,
                        tvb,
                        offset,
                        hf_rtps_sm_wrentity_id,
                        hf_rtps_sm_wrentity_id_key,
                        hf_rtps_sm_wrentity_id_kind,
                        ett_rtps_wrentity,
                        "writerEntityId",
                        NULL);
  offset += 4;

  /* First available Batch Sequence Number */
  rtps_util_add_seq_number(tree,
                        tvb,
                        offset,
                        little_endian,
                        "firstBatchSN");
  offset += 8;

  /* Last Batch Sequence Number */
  rtps_util_add_seq_number(tree,
                        tvb,
                        offset,
                        little_endian,
                        "lastBatchSN");
  offset += 8;

  /* First available Sequence Number */
  rtps_util_add_seq_number(tree,
                        tvb,
                        offset,
                        little_endian,
                        "firstSeqNumber");
  offset += 8;

  /* Last Sequence Number */
  rtps_util_add_seq_number(tree,
                        tvb,
                        offset,
                        little_endian,
                        "lastSeqNumber");
  offset += 8;

  /* Counter */
  rtps_util_add_long(tree,
                        tvb,
                        offset,
                        -1,
                        little_endian,
                        0,      /* is_hex */
                        0,      /* is_signed */
                        "count",
                        NULL,
                        0);
  info_summary_append(info_summary_text, SUBMESSAGE_HEARTBEAT_BATCH, NULL);
}


/* *********************************************************************** */
/* *                   H E A R T B E A T _ F R A G                       * */
/* *********************************************************************** */
static void dissect_HEARTBEAT_FRAG(tvbuff_t *tvb,
                gint offset,
                guint8 flags,
                gboolean little_endian,
                int octets_to_next_header,
                proto_tree *tree,
                char * info_summary_text,
                guint16 G_GNUC_UNUSED vendor_id) {
  /*
   * 0...2...........7...............15.............23...............31
   * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   * |HEARTBEAT_FRAG |X|X|X|X|X|X|X|E|      octetsToNextHeader       |
   * +---------------+---------------+---------------+---------------+
   * | EntityId readerEntityId                                       |
   * +---------------+---------------+---------------+---------------+
   * | EntityId writerEntityId                                       |
   * +---------------+---------------+---------------+---------------+
   * |                                                               |
   * + SequenceNumber writerSeqNumber                                +
   * |                                                               |
   * +---------------+---------------+---------------+---------------+
   * | FragmentNumber lastFragmentNum                                |
   * +---------------+---------------+---------------+---------------+
   * | Counter count                                                 |
   * +---------------+---------------+---------------+---------------+
   */

  rtps_util_decode_flags(tree, tvb, offset + 1, flags, HEARTBEAT_FRAG_FLAGS);

  if (octets_to_next_header < 24) {
    proto_tree_add_uint_format(tree,
                        hf_rtps_sm_octets_to_next_header,
                        tvb,
                        offset+2,
                        2,
                        octets_to_next_header,
                        "octetsToNextHeader: %u (Error: should be >= 24)",
                        octets_to_next_header);
    return;
  }


  /* Skip decoding the entire packet if (tree == NULL)
   * Note that we still need to decode the statusInfo and the writer ID
   */
  if (tree == NULL) {
    info_summary_append(info_summary_text, SUBMESSAGE_HEARTBEAT_FRAG, NULL);
    return;
  }

  proto_tree_add_item(tree,
                        hf_rtps_sm_octets_to_next_header,
                        tvb,
                        offset + 2,
                        2,
                        little_endian);
  offset += 4;

  /* readerEntityId */
  rtps_util_add_entity_id(tree,
                        tvb,
                        offset,
                        hf_rtps_sm_rdentity_id,
                        hf_rtps_sm_rdentity_id_key,
                        hf_rtps_sm_rdentity_id_kind,
                        ett_rtps_rdentity,
                        "readerEntityId",
                        NULL);
  offset += 4;

  /* writerEntityId */
  rtps_util_add_entity_id(tree,
                        tvb,
                        offset,
                        hf_rtps_sm_wrentity_id,
                        hf_rtps_sm_wrentity_id_key,
                        hf_rtps_sm_wrentity_id_kind,
                        ett_rtps_wrentity,
                        "writerEntityId",
                        NULL);
  offset += 4;

  /* First available Sequence Number */
  rtps_util_add_seq_number(tree,
                        tvb,
                        offset,
                        little_endian,
                        "writerSeqNumber");
  offset += 8;

  /* Fragment number */
  rtps_util_add_long(tree,
                        tvb,
                        offset,
                        -1,
                        little_endian,
                        0,      /* is_hex */
                        0,      /* is_signed */
                        "lastFragmentNum",
                        NULL,
                        0);
  offset += 4;

  /* Counter */
  rtps_util_add_long(tree,
                        tvb,
                        offset,
                        -1,
                        little_endian,
                        0,      /* is_hex */
                        0,      /* is_signed */
                        "count",
                        NULL,
                        0);
  info_summary_append(info_summary_text, SUBMESSAGE_HEARTBEAT_FRAG, NULL);
}



/* *********************************************************************** */
/* *                                 G A P                               * */
/* *********************************************************************** */
static void dissect_GAP(tvbuff_t *tvb,
                gint offset,
                guint8 flags,
                gboolean little_endian,
                int octets_to_next_header,
                proto_tree *tree,
                char * info_summary_text,
                guint16 G_GNUC_UNUSED vendor_id) {
  /*
   * 0...2...........7...............15.............23...............31
   * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   * |   GAP         |X|X|X|X|X|X|X|E|      octetsToNextHeader       |
   * +---------------+---------------+---------------+---------------+
   * | EntityId readerEntityId                                       |
   * +---------------+---------------+---------------+---------------+
   * | EntityId writerEntityId                                       |
   * +---------------+---------------+---------------+---------------+
   * |                                                               |
   * + SequenceNumber gapStart                                       +
   * |                                                               |
   * +---------------+---------------+---------------+---------------+
   * |                                                               |
   * ~ SequenceNumberSet gapList                                     ~
   * |                                                               |
   * +---------------+---------------+---------------+---------------+
   */

  rtps_util_decode_flags(tree, tvb, offset + 1, flags, GAP_FLAGS);

  if (octets_to_next_header < 24) {
    proto_tree_add_uint_format(tree,
                        hf_rtps_sm_octets_to_next_header,
                        tvb,
                        offset + 2,
                        2,
                        octets_to_next_header,
                        "octetsToNextHeader: %u (Error: should be >= 24)",
                        octets_to_next_header);
    return;
  }

  /* Skip decoding the entire packet if (tree == NULL)
   * Note that we still need to decode the statusInfo and the writer ID
   */
  if (tree == NULL) {
    info_summary_append(info_summary_text, SUBMESSAGE_GAP, NULL);
    return;
  }

  proto_tree_add_item(tree,
                        hf_rtps_sm_octets_to_next_header,
                        tvb,
                        offset + 2,
                        2,
                        little_endian);
  offset += 4;

  /* readerEntityId */
  rtps_util_add_entity_id(tree,
                        tvb,
                        offset,
                        hf_rtps_sm_rdentity_id,
                        hf_rtps_sm_rdentity_id_key,
                        hf_rtps_sm_rdentity_id_kind,
                        ett_rtps_rdentity,
                        "readerEntityId",
                        NULL);
  offset += 4;

  /* writerEntityId */
  rtps_util_add_entity_id(tree,
                        tvb,
                        offset,
                        hf_rtps_sm_wrentity_id,
                        hf_rtps_sm_wrentity_id_key,
                        hf_rtps_sm_wrentity_id_kind,
                        ett_rtps_wrentity,
                        "writerEntityId",
                        NULL);
  offset += 4;


 /* First Sequence Number */
  rtps_util_add_seq_number(tree,
                        tvb,
                        offset,
                        little_endian,
                        "gapStart");
  offset += 8;

  /* Bitmap */
  rtps_util_add_bitmap(tree,
                        tvb,
                        offset,
                        little_endian,
                        "gapList");
  info_summary_append(info_summary_text, SUBMESSAGE_GAP, NULL);
}


/* *********************************************************************** */
/* *                           I N F O _ T S                             * */
/* *********************************************************************** */
static void dissect_INFO_TS(tvbuff_t *tvb,
                gint offset,
                guint8 flags,
                gboolean little_endian,
                int octets_to_next_header,
                proto_tree *tree,
                char * info_summary_text,
                guint16 G_GNUC_UNUSED vendor_id) {
  /*
   * 0...2...........7...............15.............23...............31
   * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   * |   INFO_TS     |X|X|X|X|X|X|I|E|      octetsToNextHeader       |
   * +---------------+---------------+---------------+---------------+
   * |                                                               |
   * + Timestamp timestamp [only if I==1]                            +
   * |                                                               |
   * +---------------+---------------+---------------+---------------+
   */

  int min_len;
  rtps_util_decode_flags(tree, tvb, offset + 1, flags, INFO_TS_FLAGS);

  min_len = 0;
  if ((flags & FLAG_INFO_TS_T) == 0) min_len += 8;

  if (octets_to_next_header != min_len) {
    proto_tree_add_uint_format(tree,
                        hf_rtps_sm_octets_to_next_header,
                        tvb,
                        offset+2,
                        2,
                        octets_to_next_header,
                        "octetsToNextHeader: %u (Error: should be == %u)",
                        octets_to_next_header,
                        min_len);
    return;
  }

  /* Skip decoding the entire packet if (tree == NULL)
   * Note that we still need to decode the statusInfo and the writer ID
   */
  if (tree == NULL) {
    info_summary_append(info_summary_text, SUBMESSAGE_INFO_TS, NULL);
    return;
  }

  proto_tree_add_item(tree,
                        hf_rtps_sm_octets_to_next_header,
                        tvb,
                        offset + 2,
                        2,
                        little_endian);
  offset += 4;

  if ((flags & FLAG_INFO_TS_T) == 0) {
    rtps_util_add_ntp_time(tree,
                        tvb,
                        offset,
                        little_endian,
                        "timestamp",
                        NULL,
                        0);
  }
  info_summary_append(info_summary_text, SUBMESSAGE_INFO_TS, NULL);
}


/* *********************************************************************** */
/* *                           I N F O _ S R C                           * */
/* *********************************************************************** */
static void dissect_INFO_SRC(tvbuff_t *tvb,
                gint offset,
                guint8 flags,
                gboolean little_endian,
                int octets_to_next_header,
                proto_tree *tree,
                char * info_summary_text,
                guint16 G_GNUC_UNUSED vendor_id) {
  /*
   * 0...2...........7...............15.............23...............31
   * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   * |   INFO_SRC    |X|X|X|X|X|X|X|E|      octetsToNextHeader       |
   * +---------------+---------------+---------------+---------------+
   * | long unused                                                   |
   * +---------------+---------------+---------------+---------------+
   * | ProtocolVersion version       | VendorId vendor               |
   * +---------------+---------------+---------------+---------------+
   * |                                                               |
   * +                                                               +
   * | GuidPrefix guidPrefix                                         |
   * +                                                               +
   * |                                                               |
   * +---------------+---------------+---------------+---------------+
   */

  rtps_util_decode_flags(tree, tvb, offset + 1, flags, INFO_SRC_FLAGS);

  if (octets_to_next_header != 16) {
    proto_tree_add_uint_format(tree,
                        hf_rtps_sm_octets_to_next_header,
                        tvb,
                        offset+2,
                        2,
                        octets_to_next_header,
                        "octetsToNextHeader: %u (Error: should be == 16)",
                        octets_to_next_header);
    return;
  }

  /* Skip decoding the entire packet if (tree == NULL)
   * Note that we still need to decode the statusInfo and the writer ID
   */
  if (tree == NULL) {
    info_summary_append(info_summary_text, SUBMESSAGE_INFO_SRC, NULL);
    return;
  }

  proto_tree_add_item(tree,
                        hf_rtps_sm_octets_to_next_header,
                        tvb,
                        offset + 2,
                        2,
                        little_endian);
  offset += 4;

  /* Ip Address */
  {
    guint32 ip = NEXT_guint32(tvb, offset, little_endian);
    proto_tree_add_text(tree,
                        tvb,
                        offset,
                        4,
                        "unused: 0x%08x (appIpAddress: %d.%d.%d.%d)",
                        ip,
                        (ip >> 24) & 0xff,
                        (ip >> 16) & 0xff,
                        (ip >> 8) & 0xff,
                        ip & 0xff);
    offset += 4;
  }

  /* Version */
  {
    guint8 major = 0;
    guint8 minor = 0;
    major = tvb_get_guint8(tvb, offset);
    minor = tvb_get_guint8(tvb, offset+1);

    proto_tree_add_text(tree,
                        tvb,
                        offset,
                        2,
                        "version: %d.%d",
                        major,
                        minor);
    offset += 2;
  }

  /* Vendor ID */
  {
    guint8 vendor[MAX_VENDOR_ID_SIZE];
    rtps_util_add_vendor_id(NULL,
                        tvb,
                        offset,
                        vendor,
                        MAX_VENDOR_ID_SIZE);
    proto_tree_add_text(tree,
                        tvb,
                        offset,
                        2,
                        "vendor: %s",
                        vendor);
    offset += 2;
  }

  {
    /* guint8 temp_buffer[MAX_GUID_PREFIX_SIZE]; */
    rtps_util_add_guid_prefix(tree,
                        tvb,
                        offset,
                        hf_rtps_sm_guid_prefix,
                        hf_rtps_sm_host_id,
                        hf_rtps_sm_app_id,
                        hf_rtps_sm_counter,
                        NULL,   /* Use default 'guidPrefix' */
                        NULL,
                        0);
  }
  info_summary_append(info_summary_text, SUBMESSAGE_INFO_SRC, NULL);
}


/* *********************************************************************** */
/* *                    I N F O _ R E P L Y _ I P 4                      * */
/* *********************************************************************** */
static void dissect_INFO_REPLY_IP4(tvbuff_t *tvb,
                gint offset,
                guint8 flags,
                gboolean little_endian,
                int octets_to_next_header,
                proto_tree *tree,
                char * info_summary_text,
                guint16 G_GNUC_UNUSED vendor_id) {
  /*
   * 0...2...........7...............15.............23...............31
   * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   * |INFO_REPLY_IP4 |X|X|X|X|X|X|M|E|      octetsToNextHeader       |
   * +---------------+---------------+---------------+---------------+
   * |                                                               |
   * + LocatorUDPv4 unicastReplyLocator                              +
   * |                                                               |
   * +---------------+---------------+---------------+---------------+
   * |                                                               |
   * + LocatorUDPv4 multicastReplyLocator [only if M==1]             +
   * |                                                               |
   * +---------------+---------------+---------------+---------------+
   */

  int min_len;
  rtps_util_decode_flags(tree, tvb, offset + 1, flags, INFO_REPLY_IP4_FLAGS);

  min_len = 8;
  if ((flags & FLAG_INFO_REPLY_IP4_M) != 0) min_len += 8;


  if (octets_to_next_header != min_len) {
    proto_tree_add_uint_format(tree,
                        hf_rtps_sm_octets_to_next_header,
                        tvb,
                        offset+2,
                        2,
                        octets_to_next_header,
                        "octetsToNextHeader: %u (Error: should be == %u)",
                        octets_to_next_header,
                        min_len);
    return;
  }

  /* Skip decoding the entire packet if (tree == NULL)
   * Note that we still need to decode the statusInfo and the writer ID
   */
  if (tree == NULL) {
    info_summary_append(info_summary_text, SUBMESSAGE_INFO_REPLY_IP4, NULL);
    return;
  }
  proto_tree_add_item(tree,
                        hf_rtps_sm_octets_to_next_header,
                        tvb,
                        offset + 2,
                        2,
                        little_endian);
  offset += 4;


  /* unicastReplyLocator */
  rtps_util_add_locator_udp_v4(tree,
                        tvb,
                        offset,
                        "unicastReplyLocator",
                        little_endian);

  offset += 8;

  /* multicastReplyLocator */
  if ((flags & FLAG_INFO_REPLY_IP4_M) != 0) {
    rtps_util_add_locator_udp_v4(tree,
                        tvb,
                        offset,
                        "multicastReplyLocator",
                        little_endian);
    offset += 8;
  }
  info_summary_append(info_summary_text, SUBMESSAGE_INFO_REPLY_IP4, NULL);
}

/* *********************************************************************** */
/* *                           I N F O _ D S T                           * */
/* *********************************************************************** */
static void dissect_INFO_DST(tvbuff_t *tvb,
                gint offset,
                guint8 flags,
                gboolean little_endian,
                int octets_to_next_header,
                proto_tree *tree,
                char * info_summary_text,
                guint16 G_GNUC_UNUSED vendor_id) {
  /*
   * 0...2...........7...............15.............23...............31
   * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   * |   INFO_DST    |X|X|X|X|X|X|X|E|      octetsToNextHeader       |
   * +---------------+---------------+---------------+---------------+
   * |                                                               |
   * +                                                               +
   * | GuidPrefix guidPrefix                                         |
   * +                                                               +
   * |                                                               |
   * +---------------+---------------+---------------+---------------+
   */

  rtps_util_decode_flags(tree, tvb, offset + 1, flags, INFO_DST_FLAGS);

  if (octets_to_next_header != 12) {
    proto_tree_add_uint_format(tree,
                        hf_rtps_sm_octets_to_next_header,
                        tvb,
                        offset+2,
                        2,
                        octets_to_next_header,
                        "octetsToNextHeader: %u (Error: should be == 12)",
                        octets_to_next_header);
    return;
  }

  /* Skip decoding the entire packet if (tree == NULL)
   * Note that we still need to decode the statusInfo and the writer ID
   */
  if (tree == NULL) {
    info_summary_append(info_summary_text, SUBMESSAGE_INFO_DST, NULL);
    return;
  }

  proto_tree_add_item(tree,
                        hf_rtps_sm_octets_to_next_header,
                        tvb,
                        offset + 2,
                        2,
                        little_endian);
  offset += 4;

  rtps_util_add_guid_prefix(tree,
                        tvb,
                        offset,
                        hf_rtps_sm_guid_prefix,
                        hf_rtps_sm_host_id,
                        hf_rtps_sm_app_id,
                        hf_rtps_sm_counter,
                        NULL,
                        NULL,
                        0);
  info_summary_append(info_summary_text, SUBMESSAGE_INFO_DST, NULL);
}



/* *********************************************************************** */
/* *                        I N F O _ R E P L Y                          * */
/* *********************************************************************** */
static void dissect_INFO_REPLY(tvbuff_t *tvb,
                gint offset,
                guint8 flags,
                gboolean little_endian,
                int octets_to_next_header,
                proto_tree *tree,
                char * info_summary_text,
                guint16 G_GNUC_UNUSED vendor_id) {
  /*
   * 0...2...........7...............15.............23...............31
   * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   * |   INFO_REPLY  |X|X|X|X|X|X|M|E|      octetsToNextHeader       |
   * +---------------+---------------+---------------+---------------+
   * |                                                               |
   * ~ LocatorList unicastReplyLocatorList                           ~
   * |                                                               |
   * +---------------+---------------+---------------+---------------+
   * |                                                               |
   * ~ LocatorList multicastReplyLocatorList [only if M==1]          ~
   * |                                                               |
   * +---------------+---------------+---------------+---------------+
   */

  int min_len;
  rtps_util_decode_flags(tree, tvb, offset + 1, flags, INFO_REPLY_FLAGS);

  min_len = 8;
  if ((flags & FLAG_INFO_REPLY_M) != 0) min_len += 8;


  if (octets_to_next_header != min_len) {
    proto_tree_add_uint_format(tree,
                        hf_rtps_sm_octets_to_next_header,
                        tvb,
                        offset+2,
                        2,
                        octets_to_next_header,
                        "octetsToNextHeader: %u (Error: should be == %u)",
                        octets_to_next_header,
                        min_len);
    return;
  }

  /* Skip decoding the entire packet if (tree == NULL)
   * Note that we still need to decode the statusInfo and the writer ID
   */
  if (tree == NULL) {
    info_summary_append(info_summary_text, SUBMESSAGE_INFO_REPLY, NULL);
    return;
  }

  proto_tree_add_item(tree,
                        hf_rtps_sm_octets_to_next_header,
                        tvb,
                        offset + 2,
                        2,
                        little_endian);
  offset += 4;


  /* unicastReplyLocatorList */
  offset = rtps_util_add_locator_list(tree,
                        tvb,
                        offset,
                        "unicastReplyLocatorList",
                        little_endian);


  /* multicastReplyLocatorList */
  if ((flags & FLAG_INFO_REPLY_M) != 0) {
    offset = rtps_util_add_locator_list(tree,
                        tvb,
                        offset,
                        "multicastReplyLocatorList",
                        little_endian);
  }
  info_summary_append(info_summary_text, SUBMESSAGE_INFO_REPLY, NULL);
}

/* *********************************************************************** */
/* *                     R T P S _ D A T A                               * */
/* *                           A N D                                     * */
/* *             R T P S _ D A T A _ S E S S I O N                       * */
/* *********************************************************************** */
static void dissect_RTPS_DATA(tvbuff_t *tvb,
                gint offset,
                guint8 flags,
                gboolean little_endian,
                int octets_to_next_header,
                proto_tree *tree,
                char * info_summary_text,
                guint16 vendor_id,
                int is_session) {
  /*
   *
   * 0...2...........7...............15.............23...............31
   * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   * | RTPS_DATA     |X|X|X|X|K|D|Q|E|      octetsToNextHeader       |
   * +---------------+---------------+---------------+---------------+
   * | Flags extraFlags              |      octetsToInlineQos        |
   * +---------------+---------------+---------------+---------------+
   * | EntityId readerEntityId                                       |
   * +---------------+---------------+---------------+---------------+
   * | EntityId writerEntityId                                       |
   * +---------------+---------------+---------------+---------------+
   * |                                                               |
   * + SequenceNumber writerSeqNum                                   +
   * |                                                               |
   * +---------------+---------------+---------------+---------------+
   * |                                                               |
   * ~ ParameterList inlineQos [only if Q==1]                        ~
   * |                                                               |
   * +---------------+---------------+---------------+---------------+
   * |                                                               |
   * ~ SerializedData serializedData [only if D==1 || K==1]          ~
   * |                                                               |
   * +---------------+---------------+---------------+---------------+
   *
   * 0...2...........7...............15.............23...............31
   * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   * |RTPS_DATA_SESSI|X|X|X|X|K|D|Q|E|      octetsToNextHeader       |
   * +---------------+---------------+---------------+---------------+
   * | Flags extraFlags              |      octetsToInlineQos        |
   * +---------------+---------------+---------------+---------------+
   * | EntityId readerEntityId                                       |
   * +---------------+---------------+---------------+---------------+
   * | EntityId writerEntityId                                       |
   * +---------------+---------------+---------------+---------------+
   * |                                                               |
   * + SequenceNumber writerSessionSeqNum                            +
   * |                                                               |
   * +---------------+---------------+---------------+---------------+
   * |                                                               |
   * + SequenceNumber writerVirtualSeqNum                            +
   * |                                                               |
   * +---------------+---------------+---------------+---------------+
   * |                                                               |
   * ~ ParameterList inlineQos [only if Q==1]                        ~
   * |                                                               |
   * +---------------+---------------+---------------+---------------+
   * |                                                               |
   * ~ SerializedData serializedData [only if D==1 || K==1]          ~
   * |                                                               |
   * +---------------+---------------+---------------+---------------+
   */
  int min_len;
  gint old_offset = offset;
  guint32 wid;                  /* Writer EntityID */
  guint32 status_info = 0xffffffff;

  rtps_util_decode_flags(tree, tvb, offset + 1, flags, RTPS_DATA_FLAGS);

  /* Calculates the minimum length for this submessage */
  min_len = 24;
  if (is_session) {
    min_len += 8;
  }
  if ((flags & FLAG_RTPS_DATA_Q) != 0) min_len += 4;
  if ((flags & FLAG_RTPS_DATA_D) != 0) min_len += 4;
  if ((flags & FLAG_RTPS_DATA_K) != 0) min_len += 4;

  if (octets_to_next_header < min_len) {
    proto_tree_add_uint_format(tree,
                        hf_rtps_sm_octets_to_next_header,
                        tvb,
                        offset+2,
                        2,
                        octets_to_next_header,
                        "octetsToNextHeader: %u (Error: should be >= %u)",
                        octets_to_next_header,
                        min_len);
    return;
  }

  /* Skip decoding the entire packet if (tree == NULL)
   * Note that we still need to decode the statusInfo and the writer ID
   */
  if (tree == NULL) {
    offset += 12;
    /* writerEntityId */
    wid = NEXT_guint32(tvb, offset, little_endian);

    offset += 12;
    if ((flags & FLAG_RTPS_DATA_Q) != 0) {
      offset = dissect_parameter_sequence(tree,
                        tvb,
                        offset,
                        little_endian,
                        octets_to_next_header - (offset - old_offset) + 4,
                        "inlineQos",
                        &status_info,
                        vendor_id);
    }
    info_summary_append_ex(info_summary_text, SUBMESSAGE_RTPS_DATA, wid, status_info);
    return;
  }

  proto_tree_add_item(tree,
                        hf_rtps_sm_octets_to_next_header,
                        tvb,
                        offset + 2,
                        2,
                        little_endian);
  offset += 4;


  /* extraFlags */
  rtps_util_add_extra_flags(tree,
                        tvb,
                        offset,
                        "Extra flags:");
  offset += 2;

  /* octetsToInlineQos */
  proto_tree_add_text(tree,
                        tvb,
                        offset,
                        2,
                        "Octets to inline QoS: %d",
                        NEXT_guint16(tvb, offset, little_endian));
  offset += 2;


  /* readerEntityId */
  rtps_util_add_entity_id(tree,
                        tvb,
                        offset,
                        hf_rtps_sm_rdentity_id,
                        hf_rtps_sm_rdentity_id_key,
                        hf_rtps_sm_rdentity_id_kind,
                        ett_rtps_rdentity,
                        "readerEntityId",
                        NULL);
  offset += 4;

  /* writerEntityId */
  rtps_util_add_entity_id(tree,
                        tvb,
                        offset,
                        hf_rtps_sm_wrentity_id,
                        hf_rtps_sm_wrentity_id_key,
                        hf_rtps_sm_wrentity_id_kind,
                        ett_rtps_wrentity,
                        "writerEntityId",
                        &wid);
  offset += 4;

  /* Sequence number */
  if (is_session) {
    rtps_util_add_seq_number(tree,
                        tvb,
                        offset,
                        little_endian,
                        "writerSessionSeqNumber");
    offset += 8;
    rtps_util_add_seq_number(tree,
                        tvb,
                        offset,
                        little_endian,
                        "writerVirtualSeqNumber");
    offset += 8;
  } else {
    rtps_util_add_seq_number(tree,
                        tvb,
                        offset,
                        little_endian,
                        "writerSeqNumber");
    offset += 8;
  }

  /* InlineQos */
  if ((flags & FLAG_RTPS_DATA_Q) != 0) {
    offset = dissect_parameter_sequence(tree,
                        tvb,
                        offset,
                        little_endian,
                        octets_to_next_header - (offset - old_offset) + 4,
                        "inlineQos",
                        &status_info,
                        vendor_id);
  }

  /* SerializedData */
  if (((flags & FLAG_RTPS_DATA_D) != 0) || ((flags & FLAG_RTPS_DATA_K) != 0)) {
    if (wid == ENTITYID_P2P_BUILTIN_PARTICIPANT_MESSAGE_WRITER) {
      /* Dissect the serialized data as ParticipantMessageData:
       *  struct ParticipantMessageData {
       *    KeyHashPrefix_t participantGuidPrefix;
       *    KeyHashSuffix_t kind;
       *    sequence<octet> data;
       * }
       */
      proto_tree * rtps_pm_tree;
      proto_tree * guid_tree;
      guint32 kind;
      guint16 encapsulation_id;
      guint16 encapsulation_len;
      /*int encapsulation_little_endian = 0;*/
      proto_item * ti = proto_tree_add_text(tree,
                        tvb,
                        offset,
                        octets_to_next_header - (offset - old_offset) + 4,
                        "ParticipantMessageData");

      rtps_pm_tree = proto_item_add_subtree(ti, ett_rtps_part_message_data);
      /* Encapsulation ID */
      encapsulation_id =  NEXT_guint16(tvb, offset, 0);   /* Always big endian */

      proto_tree_add_text(rtps_pm_tree,
                        tvb,
                        offset,
                        2,
                        "encapsulation kind: %s",
                        val_to_str(encapsulation_id,
                        encapsulation_id_vals, "unknown (%02x)"));
      offset += 2;

#if 0 /* XXX: encapsulation_little_endian not actually used anywhere ?? */
      /* Sets the correct values for encapsulation_le */
      if (encapsulation_id == ENCAPSULATION_CDR_LE ||
          encapsulation_id == ENCAPSULATION_PL_CDR_LE) {
        encapsulation_little_endian = 1;
      }
#endif

      /* Encapsulation length (or option) */
      encapsulation_len =  NEXT_guint16(tvb, offset, 0);    /* Always big endian */
      proto_tree_add_text(rtps_pm_tree,
                        tvb,
                        offset,
                        2,
                        "encapsulation options: %04x",
                        encapsulation_len);
      offset += 2;

      guid_tree = proto_item_add_subtree(ti,
                        ett_rtps_part_message_data);

      rtps_util_add_guid_prefix(guid_tree,
                        tvb,
                        offset,
                        hf_rtps_sm_guid_prefix,
                        hf_rtps_sm_host_id,
                        hf_rtps_sm_app_id,
                        hf_rtps_sm_counter,
                        "participantGuidPrefix",
                        NULL,
                        0);
      offset += 12;

      /* Kind */
      kind =  NEXT_guint32(tvb, offset, 0);   /* Always big endian */
      proto_tree_add_text(guid_tree,
            tvb,
            offset,
            4,
            "kind: %s",
            val_to_str(kind, participant_message_data_kind, "unknown (%04x)"));
      offset += 4;

      dissect_octet_seq(rtps_pm_tree, /* guid_tree, */
                        tvb,
                        offset,
                        "serializedData");
    } else {
      const char *label;
      if (((flags & FLAG_RTPS_DATA_D) != 0) || ((flags & FLAG_RTPS_DATA_K) == 0)) {
        label = "serializedData";
      } else if (((flags & FLAG_RTPS_DATA_D) == 0) || ((flags & FLAG_RTPS_DATA_K) != 0)) {
        label = "serializedKey";
      } else {
        /* D==1 && K==1 */
        label = "<invalid or unknown data type>";
      }

      /* At the end still dissect the rest of the bytes as raw data */
      dissect_serialized_data(tree,
                        tvb,
                        offset,
                        octets_to_next_header - (offset - old_offset) + 4,
                        label,
                        vendor_id);
    }
  }

  info_summary_append_ex(info_summary_text, SUBMESSAGE_RTPS_DATA, wid, status_info);
}




/* *********************************************************************** */
/* *                 R T P S _ D A T A _ F R A G                         * */
/* *********************************************************************** */
static void dissect_RTPS_DATA_FRAG(tvbuff_t *tvb,
                gint offset,
                guint8 flags,
                gboolean little_endian,
                int octets_to_next_header,
                proto_tree *tree,
                char * info_summary_text,
                guint16 vendor_id) {
  /*
   *
   * 0...2...........7...............15.............23...............31
   * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   * |RTPS_DATA_FRAG |X|X|X|X|X|K|Q|E|      octetsToNextHeader       |
   * +---------------+---------------+---------------+---------------+
   * | Flags extraFlags              |      octetsToInlineQos        |
   * +---------------+---------------+---------------+---------------+
   * | EntityId readerEntityId                                       |
   * +---------------+---------------+---------------+---------------+
   * | EntityId writerEntityId                                       |
   * +---------------+---------------+---------------+---------------+
   * |                                                               |
   * + SequenceNumber writerSeqNum                                   +
   * |                                                               |
   * +---------------+---------------+---------------+---------------+
   * | FragmentNumber fragmentStartingNum                            |
   * +---------------+---------------+---------------+---------------+
   * | ushort fragmentsInSubmessage  | ushort fragmentSize           |
   * +---------------+---------------+---------------+---------------+
   * | unsigned long sampleSize                                      |
   * +---------------+---------------+---------------+---------------+
   * |                                                               |
   * ~ ParameterList inlineQos [only if Q==1]                        ~
   * |                                                               |
   * +---------------+---------------+---------------+---------------+
   * |                                                               |
   * ~ SerializedData serializedData                                 ~
   * |                                                               |
   * +---------------+---------------+---------------+---------------+
   */
  int min_len;
  gint old_offset = offset;
  guint32 wid;                  /* Writer EntityID */
  guint32 status_info = 0xffffffff;

  rtps_util_decode_flags(tree, tvb, offset + 1, flags, RTPS_DATA_FRAG_FLAGS);

  /* Calculates the minimum length for this submessage */
  min_len = 36;
  if ((flags & FLAG_RTPS_DATA_FRAG_Q) != 0) min_len += 4;

  if (octets_to_next_header < min_len) {
    proto_tree_add_uint_format(tree,
                        hf_rtps_sm_octets_to_next_header,
                        tvb,
                        offset+2,
                        2,
                        octets_to_next_header,
                        "octetsToNextHeader: %u (Error: should be >= %u)",
                        octets_to_next_header,
                        min_len);
    return;
  }

  /* Skip decoding the entire packet if (tree == NULL)
   * Note that we still need to decode the statusInfo and the writer ID
   */
  if (tree == NULL) {
    offset += 12;
    /* writerEntityId */
    wid = NEXT_guint32(tvb, offset, little_endian);

    offset += 24;
    if ((flags & FLAG_RTPS_DATA_FRAG_Q) != 0) {
      offset = dissect_parameter_sequence(tree,
                        tvb,
                        offset,
                        little_endian,
                        octets_to_next_header - (offset - old_offset) + 4,
                        "inlineQos",
                        &status_info,
                        vendor_id);
    }
    info_summary_append_ex(info_summary_text, SUBMESSAGE_RTPS_DATA_FRAG, wid, status_info);
    return;
  }

  proto_tree_add_item(tree,
                        hf_rtps_sm_octets_to_next_header,
                        tvb,
                        offset + 2,
                        2,
                        little_endian);
  offset += 4;


  /* extraFlags */
  rtps_util_add_extra_flags(tree,
                        tvb,
                        offset,
                        "Extra flags:");
  offset += 2;

  /* octetsToInlineQos */
  proto_tree_add_text(tree,
                        tvb,
                        offset,
                        2,
                        "Octets to inline QoS: %d",
                        NEXT_guint16(tvb, offset, little_endian));
  offset += 2;


  /* readerEntityId */
  rtps_util_add_entity_id(tree,
                        tvb,
                        offset,
                        hf_rtps_sm_rdentity_id,
                        hf_rtps_sm_rdentity_id_key,
                        hf_rtps_sm_rdentity_id_kind,
                        ett_rtps_rdentity,
                        "readerEntityId",
                        NULL);
  offset += 4;

  /* writerEntityId */
  rtps_util_add_entity_id(tree,
                        tvb,
                        offset,
                        hf_rtps_sm_wrentity_id,
                        hf_rtps_sm_wrentity_id_key,
                        hf_rtps_sm_wrentity_id_kind,
                        ett_rtps_wrentity,
                        "writerEntityId",
                        &wid);
  offset += 4;


  /* Sequence number */
  rtps_util_add_seq_number(tree,
                        tvb,
                        offset,
                        little_endian,
                        "writerSeqNumber");
  offset += 8;

  /* Fragment number */
  rtps_util_add_long(tree,
                        tvb,
                        offset,
                        -1,
                        little_endian,
                        0,      /* is_hex */
                        0,      /* is_signed */
                        "fragmentStartingNum",
                        NULL,
                        0);
  offset += 4;

  /* Fragments in submessage */
  rtps_util_add_short(tree,
                        tvb,
                        offset,
                        -1,
                        little_endian,
                        0,      /* is_hex */
                        0,      /* is_signed */
                        "fragmentsInSubmessage",
                        NULL,
                        0);
  offset += 2;

  /* Fragment size */
  rtps_util_add_short(tree,
                        tvb,
                        offset,
                        -1,
                        little_endian,
                        0,      /* is_hex */
                        0,      /* is_signed */
                        "fragmentSize",
                        NULL,
                        0);
  offset += 2;

  /* sampleSize */
  rtps_util_add_long(tree,
                        tvb,
                        offset,
                        -1,
                        little_endian,
                        0,      /* is_hex */
                        0,      /* is_signed */
                        "sampleSize",
                        NULL,
                        0);
  offset += 4;

  /* InlineQos */
  if ((flags & FLAG_RTPS_DATA_FRAG_Q) != 0) {
    offset = dissect_parameter_sequence(tree,
                        tvb,
                        offset,
                        little_endian,
                        octets_to_next_header - (offset - old_offset) + 4,
                        "inlineQos",
                        &status_info,
                        vendor_id);
  }

  /* SerializedData */
  {
    const char *label = "serializedData";
    if ((flags & FLAG_RTPS_DATA_FRAG_K) != 0) {
      label = "serializedKey";
    }
    dissect_serialized_data(tree,
                        tvb,
                        offset,
                        octets_to_next_header - (offset - old_offset) + 4,
                        label,
                        vendor_id);
  }
  info_summary_append_ex(info_summary_text, SUBMESSAGE_RTPS_DATA_FRAG, wid, status_info);
}




/* *********************************************************************** */
/* *                 R T P S _ D A T A _ B A T C H                       * */
/* *********************************************************************** */
static void dissect_RTPS_DATA_BATCH(tvbuff_t *tvb,
                gint offset,
                guint8 flags,
                gboolean little_endian,
                int octets_to_next_header,
                proto_tree *tree,
                char * info_summary_text,
                guint16 vendor_id) {
  /*
   *
   * 0...2...........7...............15.............23...............31
   * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   * |RTPS_DATA_BATCH|X|X|X|X|X|X|Q|E|      octetsToNextHeader       |
   * +---------------+---------------+---------------+---------------+
   * |   Flags          extraFlags   |     octetsToInlineQos         |
   * +---------------+---------------+---------------+---------------+
   * |         EntityId               readerId                       |
   * +---------------+---------------+---------------+---------------+
   * |         EntityId               writerId                       |
   * +---------------+---------------+---------------+---------------+
   * |                                                               |
   * +         SequenceNumber         batchSN                        +
   * |                                                               |
   * +---------------+---------------+---------------+---------------+
   * |                                                               |
   * +         SequenceNumber         firstSampleSN                  +
   * |                                                               |
   * +---------------+---------------+---------------+---------------+
   * |         SequenceNumberOffset   offsetToLastSampleSN           |
   * +---------------+---------------+---------------+---------------+
   * |         unsigned long          batchSampleCount               |
   * +---------------+---------------+---------------+---------------+
   * |                                                               |
   * ~         ParameterList          batchInlineQos  [only if Q==1] ~
   * |                                                               |
   * +---------------+---------------+---------------+---------------+
   * |         unsigned long          octetsToSLEncapsulationId      |
   * +---------------+---------------+---------------+---------------+
   * |                                                               |
   * ~         SampleInfoList         sampleInfoList                 ~
   * |                                                               |
   * +---------------+---------------+---------------+---------------+
   * |   SampleListEncapsulationId   |                               |
   * +---------------+---------------+---------------+---------------+
   * |                                                               |
   * ~         SampleList             sampleList                     ~
   * |                                                               |
   * +---------------+---------------+---------------+---------------+
   *
   *
   * SampleInfo:
   * 0...............8..............16..............24..............32
   * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   * |X|X|X|X|X|X|X|X|X|X|K|I|D|O|Q|T|       octetsToInlineQoS       |
   * +---------------+---------------+---------------+---------------+
   * |   unsigned long  serializedDataLength                         |
   * +---------------+---------------+---------------+---------------+
   * |                                                               |
   * +       Timestamp                timestamp       [only if T==1] +
   * |                                                               |
   * +---------------+---------------+---------------+---------------+
   * |      SequenceNumberOffset      offsetSN        [only if O==1] |
   * +---------------+---------------+---------------+---------------+
   * |                                                               |
   * ~      ParameterList             sampleInlineQos [only if Q==1] ~
   * |                                                               |
   * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   *
   *
   * Sample:
   * 0...............8..............16..............24..............32
   * +---------------+---------------+---------------+---------------+
   * |                                                               |
   * ~   SerializedData   serializedData [sampleInfo D==1 || K==1]   ~
   * |                                                               |
   * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   */

  int min_len;
  gint old_offset = offset;
  guint32 wid;                  /* Writer EntityID */
  guint32 status_info = 0xffffffff;
  gint32 octectsToSLEncapsulationId;
  /*guint32 batchSampleCount;*/
  gint32 sampleListOffset;
  guint16 encapsulation_id;
  guint16 *sample_info_flags = NULL;
  guint32 *sample_info_length = NULL;
  gint32  sample_info_count = 0;
  gint32  sample_info_max = rtps_max_batch_samples_dissected;

  rtps_util_decode_flags(tree, tvb, offset + 1, flags, RTPS_DATA_BATCH_FLAGS);

  /* Calculates the minimum length for this submessage */
  min_len = 44;
  if ((flags & FLAG_RTPS_DATA_BATCH_Q) != 0) min_len += 4;

  if (octets_to_next_header < min_len) {
    proto_tree_add_uint_format(tree,
                        hf_rtps_sm_octets_to_next_header,
                        tvb,
                        offset+2,
                        2,
                        octets_to_next_header,
                        "octetsToNextHeader: %u (Error: should be >= %u)",
                        octets_to_next_header,
                        min_len);
    return;
  }

  /* Skip decoding the entire packet if (tree == NULL)
   * Note that we still need to decode the statusInfo and the writer ID
   */
  if (tree == NULL) {
    offset += 12;
    /* writerEntityId */
    wid = NEXT_guint32(tvb, offset, little_endian);

    offset += 24;
    if ((flags & FLAG_DATA_Q) != 0) {
      offset = dissect_parameter_sequence(tree,
                        tvb,
                        offset,
                        little_endian,
                        octets_to_next_header - (offset - old_offset) + 4,
                        "inlineQos",
                        &status_info,
                        vendor_id);
    }
    info_summary_append_ex(info_summary_text, SUBMESSAGE_RTPS_DATA_BATCH, wid, status_info);
    return;
  }
  proto_tree_add_item(tree,
                        hf_rtps_sm_octets_to_next_header,
                        tvb,
                        offset + 2,
                        2,
                        little_endian);
  offset += 4;


  /* extraFlags */
  rtps_util_add_extra_flags(tree,
                        tvb,
                        offset,
                        "Extra flags:");
  offset += 2;

  /* octetsToInlineQos */
  proto_tree_add_text(tree,
                        tvb,
                        offset,
                        2,
                        "Octets to inline QoS: %d",
                        NEXT_guint16(tvb, offset, little_endian));
  offset += 2;


  /* readerEntityId */
  rtps_util_add_entity_id(tree,
                        tvb,
                        offset,
                        hf_rtps_sm_rdentity_id,
                        hf_rtps_sm_rdentity_id_key,
                        hf_rtps_sm_rdentity_id_kind,
                        ett_rtps_rdentity,
                        "readerEntityId",
                        NULL);
  offset += 4;

  /* writerEntityId */
  rtps_util_add_entity_id(tree,
                        tvb,
                        offset,
                        hf_rtps_sm_wrentity_id,
                        hf_rtps_sm_wrentity_id_key,
                        hf_rtps_sm_wrentity_id_kind,
                        ett_rtps_wrentity,
                        "writerEntityId",
                        &wid);
  offset += 4;


  /* Batch sequence number */
  rtps_util_add_seq_number(tree,
                        tvb,
                        offset,
                        little_endian,
                        "batchSeqNumber");
  offset += 8;

  /* First stample sequence number */
  rtps_util_add_seq_number(tree,
                        tvb,
                        offset,
                        little_endian,
                        "firstSampleSeqNumber");
  offset += 8;

  /* offsetToLastSampleSN */
  rtps_util_add_long(tree,
                        tvb,
                        offset,
                        -1,
                        little_endian,
                        0,      /* is_hex */
                        0,      /* is_signed */
                        "offsetToLastSampleSN",
                        NULL,
                        0);
  offset += 4;

  /* batchSampleCount */
  /*batchSampleCount =*/ rtps_util_add_long(tree,
                        tvb,
                        offset,
                        -1,
                        little_endian,
                        0,      /* is_hex */
                        0,      /* is_signed */
                        "batchSampleCount",
                        NULL,
                        0);
  offset += 4;

  /* Parameter list (if Q==1) */
  /* InlineQos */
  if ((flags & FLAG_RTPS_DATA_BATCH_Q) != 0) {
    offset = dissect_parameter_sequence(tree,
                        tvb,
                        offset,
                        little_endian,
                        octets_to_next_header - (offset - old_offset) + 4,
                        "batchInlineQos",
                        &status_info,
                        vendor_id);
  }

  /* octetsToSLEncapsulationId */
  octectsToSLEncapsulationId = (gint32)rtps_util_add_long(tree,
                        tvb,
                        offset,
                        -1,
                        little_endian,
                        0,      /* is_hex */
                        0,      /* is_signed */
                        "octetsToSLEncapsulationId",
                        NULL,
                        0);
  offset += 4;
  sampleListOffset = offset + octectsToSLEncapsulationId;


  /* Sample info list */
  {
    proto_item * ti;
    proto_tree * sil_tree;
    sample_info_count = 0;

    ti = proto_tree_add_text(tree,
                        tvb,
                        offset,
                        -1,
                        "Sample Info List");
    sil_tree = proto_item_add_subtree(ti, ett_rtps_sample_info_list);

    /* Allocate sample_info_flags and sample_info_length
     * to store a copy of the flags for each sample info */
    if (rtps_max_batch_samples_dissected == 0) {
      sample_info_max = 1024;   /* Max size of sampleInfo shown */
    }
    sample_info_flags = (guint16 *)ep_alloc(sizeof(guint16) * sample_info_max);
    sample_info_length = (guint32 *)ep_alloc(sizeof(guint32) * sample_info_max);

    /* Sample Info List: start decoding the sample info list until the offset
     * is greater or equal than 'sampleListOffset' */
    while (offset < sampleListOffset) {
      guint16 flags2;
      /*guint16 octetsToInlineQos;*/
      gint min_length;
      proto_tree * si_tree;
      gint offset_begin_sampleinfo = offset;

      if (rtps_max_batch_samples_dissected > 0 && (guint)sample_info_count >= rtps_max_batch_samples_dissected) {
        proto_tree_add_text(sil_tree,
                            tvb,
                            offset,
                            -1,
                            "... (more samples available. Configure this limit from preferences dialog)");
        offset = sampleListOffset;
        break;
      }

      ti = proto_tree_add_text(sil_tree,
                        tvb,
                        offset,
                        -1,
                        "sampleInfo[%d]", sample_info_count);
      si_tree = proto_item_add_subtree(ti, ett_rtps_sample_info);

      flags2 = NEXT_guint16(tvb, offset, 0); /* Flags are always big endian */
      sample_info_flags[sample_info_count] = flags2;
      rtps_util_decode_flags_16bit(si_tree, tvb, offset, flags2, RTPS_SAMPLE_INFO_FLAGS16);
      offset += 2;
      /*octetsToInlineQos =*/ rtps_util_add_short(si_tree,
                        tvb,
                        offset,
                        -1,
                        little_endian,
                        0,      /* is_hex */
                        0,      /* is_signed */
                        "octetsToInlineQos",
                        NULL,
                        0);
      offset += 2;

      min_length = 4;
      if ((flags2 & FLAG_SAMPLE_INFO_T) != 0) min_len += 8;
      if ((flags2 & FLAG_SAMPLE_INFO_Q) != 0) min_len += 4;
      if ((flags2 & FLAG_SAMPLE_INFO_O) != 0) min_len += 4;

      /* Ensure there are enough bytes to decode */
      if (sampleListOffset - offset < min_length) {
        proto_tree_add_text(si_tree,
                        tvb,
                        offset-4,
                        4,
                        "Error: not enough bytes to dissect sample info");
        return;
      }

      /* Serialized data length */
      sample_info_length[sample_info_count] = rtps_util_add_long(si_tree,
                        tvb,
                        offset,
                        -1,
                        little_endian,
                        0,      /* is_hex */
                        0,      /* is_signed */
                        "serializedDataLength",
                        NULL,
                        0);
      offset += 4;

      /* Timestamp [only if T==1] */
      if ((flags2 & FLAG_SAMPLE_INFO_T) != 0) {
        rtps_util_add_ntp_time(si_tree,
                        tvb,
                        offset,
                        little_endian,
                        "timestamp",
                        NULL,
                        0);
        offset += 8;
      }

      /* Offset SN [only if O==1] */
      if ((flags2 & FLAG_SAMPLE_INFO_O) != 0) {
        rtps_util_add_long(si_tree,
                        tvb,
                        offset,
                        -1,
                        little_endian,
                        0,      /* is_hex */
                        0,      /* is_signed */
                        "offsetSN",
                        NULL,
                        0);
        offset += 4;
      }

      /* Parameter list [only if Q==1] */
      if ((flags2 & FLAG_SAMPLE_INFO_Q) != 0) {
        offset = dissect_parameter_sequence(si_tree,
                        tvb,
                        offset,
                        little_endian,
                        octets_to_next_header - (offset - old_offset) + 4,
                        "sampleInlineQos",
                        &status_info,
                        vendor_id);
      }
      proto_item_set_len(ti, offset - offset_begin_sampleinfo);
      sample_info_count++;
    } /*   while (offset < sampleListOffset) */
  }

  /* Encapsulation ID for the entire data sequence */
  encapsulation_id =  NEXT_guint16(tvb, offset, 0);   /* Always big endian */
  proto_tree_add_text(tree,
                        tvb,
                        offset,
                        2,
                        "encapsulation kind: %s",
                        val_to_str(encapsulation_id, encapsulation_id_vals, "unknown (%02x)"));
  offset += 2;

  /* The next two bytes are ignored */
  offset += 2;

  /* Now the list of serialized data:
   * Serialized data is allocated one after another one.
   * We need to use the data previously stored in the sampleInfo to detect the
   * kind and size.
   *  - sample_info_flags -> Array of guint16 holding the flags for this sample info
   *  - sample_info_length -> Array of guint32 with the size of this sample info
   *  - sample_info_count -> size of the above arrays
   * This section will NEVER dissect more than 'sample_info_count'.
   * Note, if there are not enough bytes in the buffer, don't dissect it (this
   * can happen for example when a DISPOSE message is sent, there are sample
   * info records, but the payload size is zero for all of them)
   */
  if (octets_to_next_header - (offset - old_offset) > 0) {
    proto_item * ti;
    proto_tree * sil_tree;
    gint count = 0;
    const char * label;

    ti = proto_tree_add_text(tree,
                        tvb,
                        offset,
                        -1,
                        "Serialized Sample List");
    sil_tree = proto_item_add_subtree(ti, ett_rtps_sample_batch_list);
    for (count = 0; count < sample_info_count; ++count) {
      /* Ensure there are enough bytes in the buffer to dissect the next sample */
      if (octets_to_next_header - (offset - old_offset) + 4 < (gint)sample_info_length[count]) {
        proto_tree_add_text(sil_tree,
                        tvb,
                        offset,
                        4,
                        "Error: not enough bytes to dissect sample");
        return;
      }

      if ((sample_info_flags[count] & FLAG_SAMPLE_INFO_K) != 0) {
        label = "serializedKey[%d]";
      } else {
        label = "serializedData[%d]";
      }
      proto_tree_add_text(sil_tree,
                          tvb,
                          offset,
                          sample_info_length[count],
                          label,
                          count);
      offset += sample_info_length[count];
    }
  }
  info_summary_append_ex(info_summary_text, SUBMESSAGE_RTPS_DATA_BATCH, wid, status_info);
}





/***************************************************************************/
/* The main packet dissector function
 */
static gboolean dissect_rtps(tvbuff_t *tvb,
                        packet_info *pinfo,
                        proto_tree *tree) {
  proto_item       *ti = NULL;
  proto_tree       *rtps_tree = NULL;
  gint             offset = 0;
  proto_tree       *rtps_submessage_tree = NULL;
  guint8           submessageId;
  guint8           flags;
  gboolean         little_endian;
  gboolean         is_ping = FALSE;
  gint             next_submsg, octets_to_next_header;
  guint16          vendor_id = RTPS_VENDOR_UNKNOWN;
  char             info_summary_text[MAX_SUMMARY_SIZE];

  info_summary_text[0] = '\0';

  /* Check 'RTPS' signature:
   * A header is invalid if it has less than 16 octets
   */
  if (!tvb_bytes_exist(tvb, offset, 16)) return FALSE;

  /* Check packet signature */
  if ( (tvb_get_guint8(tvb,offset) != 'R') ||
       (tvb_get_guint8(tvb,offset+1) != 'T') ||
       (tvb_get_guint8(tvb,offset+2) != 'P') ||
       (tvb_get_guint8(tvb,offset+3) != 'S') ||
       (tvb_get_guint8(tvb,offset+4) != 2) ) {
    return FALSE;
  }

  /* --- Make entries in Protocol column ---*/
  col_set_str(pinfo->cinfo, COL_PROTOCOL, "RTPS2");
  col_clear(pinfo->cinfo, COL_INFO);

  /* Check if is NDDSPING */
  {
    guint8 nddsPing[8];
    tvb_memcpy(tvb, nddsPing, offset+8, 8);
    is_ping = (nddsPing[0] == 'N' &&
               nddsPing[1] == 'D' &&
               nddsPing[2] == 'D' &&
               nddsPing[3] == 'S' &&
               nddsPing[4] == 'P' &&
               nddsPing[5] == 'I' &&
               nddsPing[6] == 'N' &&
               nddsPing[7] == 'G');
  }

  if (tree) {
    /* create display subtree for the protocol */
    ti = proto_tree_add_item(tree, proto_rtps, tvb, 0, -1, FALSE);
    rtps_tree = proto_item_add_subtree(ti, ett_rtps);

    /*  Protocol Version */
    rtps_util_add_protocol_version(rtps_tree, tvb, offset+4);

    /*  Vendor Id  */
    vendor_id = NEXT_guint16(tvb, offset+6, FALSE);
    rtps_util_add_vendor_id(rtps_tree, tvb, offset+6, NULL, 0);

    /* If is not PING, the next 12 bytes are the GUID prefix */
    if (!is_ping) {
      rtps_util_add_guid_prefix(rtps_tree,
                        tvb,
                        offset+8,
                        hf_rtps_guid_prefix,
                        hf_rtps_host_id,
                        hf_rtps_app_id,
                        hf_rtps_sm_counter,
                        NULL,
                        NULL,
                        0);
    }
  }

  if (is_ping) {
    g_strlcpy(info_summary_text, "PING", MAX_SUMMARY_SIZE);
  }
#ifdef RTI_BUILD
  else {
    pinfo->guid_prefix_host = tvb_get_ntohl(tvb, offset + 8);
    pinfo->guid_prefix_app  = tvb_get_ntohl(tvb, offset + 12);
    pinfo->guid_prefix_count = tvb_get_ntohl(tvb, offset + 16);
    pinfo->guid_rtps2 = 1;
  }
#endif

  /* Extract the domain id and participant index for the default mapping */
  if (tree) {
    int domain_id;
    int participant_idx = -1;
    int nature;
    int Doffset;
    proto_item *ti2;
    proto_tree *mapping_tree;

    /* For a complete description of these rules, see RTPS documentation

       RTPS 1.2 mapping:
        domain_id = ((pinfo->destport - PORT_BASE)/10) % 100;
        participant_idx = (pinfo->destport - PORT_BASE) / 1000;
        nature    = (pinfo->destport % 10);

       For Unicast, the port mapping formula is:
         metatraffic_unicast_port = port_base +
                                    (domain_id_gain * domain_id) +
                                    (participant_id_gain * participant_id) +
                                    builtin_unicast_port_offset
       For Multicast, the port mapping is:
         metatraffic_multicast_port = port_base +
                                    (domain_id_gain * domain_id) +
                                     builtin_multicast_port_offset

       Where the constants are:
            port_base = 7400
            domain_id_gain = 250
            participant_id_gain = 2
            builtin_multicast_port_offset = 0
            builtin_unicast_port_offset = 10
            user_multicast_port_offset = 1
            user_unicast_port_offset = 11


       To obtain the individual components from the port number, the reverse formulas are:
            domain_id = (port - port_base) / 250        (valid both multicast / unicast)
            Doffset = (port - port_Base - (domain_id * 250));
            participant_idx = (Doffset - 10) / 2;

     */
    domain_id = (pinfo->destport - PORT_BASE) / 250;
    Doffset = (pinfo->destport - PORT_BASE - domain_id * 250);
    if (Doffset == 0) {
      nature = PORT_METATRAFFIC_MULTICAST;
    } else if (Doffset == 1) {
      nature = PORT_USERTRAFFIC_MULTICAST;
    } else {
      participant_idx = (Doffset - 10) / 2;
      if ( (Doffset - 10) % 2 == 0) {
        nature = PORT_METATRAFFIC_UNICAST;
      } else {
        nature = PORT_USERTRAFFIC_UNICAST;
      }
    }

    if (nature == PORT_METATRAFFIC_UNICAST || nature == PORT_USERTRAFFIC_UNICAST) {
      ti2 = proto_tree_add_text(rtps_tree,
                        tvb,
                        0,
                        4,
                        "Default port mapping: %s, domainId=%d, "
                        "participantIdx=%d",
                        val_to_str(nature, nature_type_vals, "%02x"),
                        domain_id,
                        participant_idx);
    } else {
      /* Multicast doesn't print the participant index */
      ti2 = proto_tree_add_text(rtps_tree,
                        tvb,
                        0,
                        4,
                        "Default port mapping: %s, domainId=%d",
                        val_to_str(nature, nature_type_vals, "%02x"),
                        domain_id);
    }

    /* Build the searchable protocol tree */
    mapping_tree = proto_item_add_subtree(ti2, ett_rtps_default_mapping);
    proto_tree_add_uint(mapping_tree,
                        hf_rtps_domain_id,
                        tvb,
                        0,
                        4,
                        domain_id);
    if (nature == PORT_METATRAFFIC_UNICAST || nature == PORT_USERTRAFFIC_UNICAST) {
      proto_tree_add_uint(mapping_tree,
                        hf_rtps_participant_idx,
                        tvb,
                        0,
                        4,
                        participant_idx);
    }
    proto_tree_add_uint(mapping_tree,
                        hf_rtps_nature_type,
                        tvb,
                        0,
                        4,
                        nature);
  }

  /* offset behind RTPS's Header (need to be set in case tree=NULL)*/
  offset=20;

  while (tvb_reported_length_remaining(tvb, offset) > 0) {
    submessageId = tvb_get_guint8(tvb, offset);

    /* Creates the subtree 'Submessage: XXXX' */
    if (rtps_tree) {
      if (submessageId & 0x80) {
        ti = proto_tree_add_text(rtps_tree,
                tvb,
                offset,
                -1,
                "Submessage: %s",
                val_to_str(submessageId, submessage_id_vals,
                        "Vendor-specific (0x%02x)"));
      } else {
        ti = proto_tree_add_text(rtps_tree,
                tvb,
                offset,
                -1,
                "Submessage: %s",
                val_to_str(submessageId, submessage_id_vals,
                        "Unknown (0x%02x)"));
      }
      rtps_submessage_tree = proto_item_add_subtree(ti, ett_rtps_submessage);

      /* Decode the submessage ID */
      if (submessageId & 0x80) {
        proto_tree_add_uint_format(rtps_submessage_tree,
                hf_rtps_sm_id,
                tvb,
                offset,
                1,
                submessageId,
                "submessageId: Vendor-specific (0x%02x)",
                      submessageId);
      } else {
        proto_tree_add_uint(rtps_submessage_tree, hf_rtps_sm_id,
                          tvb, offset, 1, submessageId);
      }
    } /* tree is present */

    /* Gets the flags */
    flags = tvb_get_guint8(tvb, offset + 1);

    /* Gets the E (Little endian) flag */
    little_endian = ((flags & FLAG_E) != 0);

    /* octet-to-next-header */
    octets_to_next_header  = NEXT_guint16(tvb, offset + 2, little_endian);
    next_submsg = offset + octets_to_next_header + 4;

    /* Set length of this item */
    if (ti != NULL) {
      proto_item_set_len(ti, octets_to_next_header + 4);
    }

    /* Now decode each single submessage
     *
     * Note: if tree==NULL, it's true we don't care too much about the
     *      details, but we are still calling the individual submessage
     *      dissectors in order to correctly compose the INFO list.
     * The offset passed to the dissectors points to the start of the
     * submessage (at the ID byte).
     */
    switch (submessageId) {
      case SUBMESSAGE_PAD:
        dissect_PAD(tvb,
                        offset,
                        flags,
                        little_endian,
                        octets_to_next_header,
                        rtps_submessage_tree,
                        info_summary_text,
                        vendor_id);
        break;

      case SUBMESSAGE_DATA:
        dissect_DATA(tvb,
                        offset,
                        flags,
                        little_endian,
                        octets_to_next_header,
                        rtps_submessage_tree,
                        info_summary_text,
                        vendor_id);
        break;

      case SUBMESSAGE_DATA_FRAG:
        dissect_DATA_FRAG(tvb,
                        offset,
                        flags,
                        little_endian,
                        octets_to_next_header,
                        rtps_submessage_tree,
                        info_summary_text,
                        vendor_id);
        break;

      case SUBMESSAGE_NOKEY_DATA:
        dissect_NOKEY_DATA(tvb,
                        offset,
                        flags,
                        little_endian,
                        octets_to_next_header,
                        rtps_submessage_tree,
                        info_summary_text,
                        vendor_id);
        break;

      case SUBMESSAGE_NOKEY_DATA_FRAG:
        dissect_NOKEY_DATA_FRAG(tvb,
                        offset,
                        flags,
                        little_endian,
                        octets_to_next_header,
                        rtps_submessage_tree,
                        info_summary_text,
                        vendor_id);
        break;

      case SUBMESSAGE_NACK_FRAG:
        dissect_NACK_FRAG(tvb,
                        offset,
                        flags,
                        little_endian,
                        octets_to_next_header,
                        rtps_submessage_tree,
                        info_summary_text,
                        vendor_id);
        break;


      case SUBMESSAGE_ACKNACK_SESSION:
      case SUBMESSAGE_ACKNACK_BATCH:
      case SUBMESSAGE_ACKNACK:
        dissect_ACKNACK(tvb,
                        offset,
                        flags,
                        little_endian,
                        octets_to_next_header,
                        rtps_submessage_tree,
                        info_summary_text,
                        vendor_id);
        break;

      case SUBMESSAGE_HEARTBEAT:
        dissect_HEARTBEAT(tvb,
                        offset,
                        flags,
                        little_endian,
                        octets_to_next_header,
                        rtps_submessage_tree,
                        info_summary_text,
                        vendor_id);
        break;

      case SUBMESSAGE_HEARTBEAT_SESSION:
      case SUBMESSAGE_HEARTBEAT_BATCH:
        dissect_HEARTBEAT_BATCH(tvb,
                        offset,
                        flags,
                        little_endian,
                        octets_to_next_header,
                        rtps_submessage_tree,
                        info_summary_text,
                        vendor_id);
        break;

      case SUBMESSAGE_HEARTBEAT_FRAG:
        dissect_HEARTBEAT_FRAG(tvb,
                        offset,
                        flags,
                        little_endian,
                        octets_to_next_header,
                        rtps_submessage_tree,
                        info_summary_text,
                        vendor_id);
        break;

      case SUBMESSAGE_GAP:
        dissect_GAP(tvb,
                        offset,
                        flags,
                        little_endian,
                        octets_to_next_header,
                        rtps_submessage_tree,
                        info_summary_text,
                        vendor_id);
        break;

      case SUBMESSAGE_INFO_TS:
        dissect_INFO_TS(tvb,
                        offset,
                        flags,
                        little_endian,
                        octets_to_next_header,
                        rtps_submessage_tree,
                        info_summary_text,
                        vendor_id);
        break;

      case SUBMESSAGE_INFO_SRC:
        dissect_INFO_SRC(tvb,
                        offset,
                        flags,
                        little_endian,
                        octets_to_next_header,
                        rtps_submessage_tree,
                        info_summary_text,
                        vendor_id);
        break;

      case SUBMESSAGE_INFO_REPLY_IP4:
        dissect_INFO_REPLY_IP4(tvb,
                        offset,
                        flags,
                        little_endian,
                        octets_to_next_header,
                        rtps_submessage_tree,
                        info_summary_text,
                        vendor_id);
        break;

      case SUBMESSAGE_INFO_DST:
        dissect_INFO_DST(tvb,
                        offset,
                        flags,
                        little_endian,
                        octets_to_next_header,
                        rtps_submessage_tree,
                        info_summary_text,
                        vendor_id);
        break;

      case SUBMESSAGE_INFO_REPLY:
        dissect_INFO_REPLY(tvb,
                        offset,
                        flags,
                        little_endian,
                        octets_to_next_header,
                        rtps_submessage_tree,
                        info_summary_text,
                        vendor_id);
        break;

      case SUBMESSAGE_RTPS_DATA_SESSION:
      case SUBMESSAGE_RTPS_DATA:
        dissect_RTPS_DATA(tvb,
                        offset,
                        flags,
                        little_endian,
                        octets_to_next_header,
                        rtps_submessage_tree,
                        info_summary_text,
                        vendor_id,
                        (submessageId == SUBMESSAGE_RTPS_DATA_SESSION));
        break;

      case SUBMESSAGE_RTPS_DATA_FRAG:
        dissect_RTPS_DATA_FRAG(tvb,
                        offset,
                        flags,
                        little_endian,
                        octets_to_next_header,
                        rtps_submessage_tree,
                        info_summary_text,
                        vendor_id);
        break;

      case SUBMESSAGE_RTPS_DATA_BATCH:
        dissect_RTPS_DATA_BATCH(tvb,
                        offset,
                        flags,
                        little_endian,
                        octets_to_next_header,
                        rtps_submessage_tree,
                        info_summary_text,
                        vendor_id);
        break;


      default:
        if (rtps_submessage_tree != NULL) {
          proto_tree_add_uint(rtps_submessage_tree, hf_rtps_sm_flags,
                          tvb, offset + 1, 1, flags);
          proto_tree_add_uint(rtps_submessage_tree,
                          hf_rtps_sm_octets_to_next_header,
                          tvb, offset + 2, 2, next_submsg);
        }
    }

     /* next submessage's offset */
     offset = next_submsg;
  }

  /* Compose the content of the 'summary' column */
  col_add_str(pinfo->cinfo, COL_INFO, info_summary_text);
  return TRUE;

}  /* dissect_rtps(...) */





/***************************************************************************
 * Register the protocol with Wireshark
 * ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
 */
void proto_register_rtps2(void) {

  /* Definition of the protocol tree items:
   * This section declares all the protocol items that are parsed in the
   * dissectors.
   * Structure of each element:
   *  {
   *    item_id,  {
   *        name,      // As appears in the GUI tree
   *        abbrev,    // Referenced by filters (rtps.xxxx[.yyyy])
   *        type,      // FT_BOOLEAN, FT_UINT8, ...
   *        display,   // BASE_HEX | BASE_DEC | BASE_OCT or other meanings
   *        strings,   // String table (for enums) or NULL
   *        bitmask,   // only for bitfields
   *        blurb,     // Complete description of this item
   *        HFILL
   *    }
   *  }
   */
  static hf_register_info hf[] = {

    /* Protocol Version (composed as major.minor) -------------------------- */
    { &hf_rtps_protocol_version, {
        "version",
        "rtps2.version",
        FT_NONE,
        BASE_NONE,
        NULL,
        0,
        "RTPS protocol version number",
        HFILL }
    },
    { &hf_rtps_protocol_version_major, {
        "major",
        "rtps2.version.major",
        FT_INT8,
        BASE_DEC,
        NULL,
        0,
        "RTPS major protocol version number",
        HFILL }
    },
    { &hf_rtps_protocol_version_minor, {
        "minor",
        "rtps2.version.minor",
        FT_INT8,
        BASE_DEC,
        NULL,
        0,
        "RTPS minor protocol version number",
        HFILL }
    },

    /* Domain Participant and Participant Index ---------------------------- */
    { &hf_rtps_domain_id, {
        "domain_id",
        "rtps2.domain_id",
        FT_UINT32,
        BASE_DEC,
        NULL,
        0,
        "Domain ID",
        HFILL }
    },

    { &hf_rtps_participant_idx, {
        "participant_idx",
        "rtps2.participant_idx",
        FT_UINT32,
        BASE_DEC,
        NULL,
        0,
        "Participant index",
        HFILL }
    },
    { &hf_rtps_nature_type, {
        "traffic_nature",
        "rtps2.traffic_nature",
        FT_UINT32,
        BASE_DEC,
        VALS(nature_type_vals),
        0,
        "Nature of the traffic (meta/user-traffic uni/multi-cast)",
        HFILL }
    },

    /* Vendor ID ----------------------------------------------------------- */
    { &hf_rtps_vendor_id, {
        "vendorId",
        "rtps2.vendorId",
        FT_UINT16,
        BASE_HEX,
        NULL,
        0,
        "Unique identifier of the DDS vendor that generated this packet",
        HFILL }
    },

    /* Guid Prefix for the Packet ------------------------------------------ */
    { &hf_rtps_guid_prefix, {
        "guidPrefix",
        "rtps2.guidPrefix",
        FT_BYTES,
        BASE_NONE,
        NULL,
        0,
        "GuidPrefix of the RTPS packet",
        HFILL }
    },

    /* Host ID ------------------------------------------------------------- */
    { &hf_rtps_host_id, {               /* HIDDEN */
        "hostId",
        "rtps2.hostId",
        FT_UINT32,
        BASE_HEX,
        NULL,
        0,
        "Sub-component 'hostId' of the GuidPrefix of the RTPS packet",
        HFILL }
    },

    /* AppID --------------------------------------------------------------- */
    { &hf_rtps_app_id, {
        "appId",
        "rtps2.appId",
        FT_UINT32,
        BASE_HEX,
        NULL,
        0,
        "Sub-component 'appId' of the GuidPrefix of the RTPS packet",
        HFILL }
    },

    /* Counter ------------------------------------------------------------- */
    { &hf_rtps_counter, {               /* HIDDEN */
        "counter",
        "rtps2.counter",
        FT_UINT32,
        BASE_HEX,
        NULL,
        0,
        "Sub-component 'counter' of the GuidPrefix of the RTPS packet",
        HFILL }
    },


    /* Submessage ID ------------------------------------------------------- */
    { &hf_rtps_sm_id, {
        "submessageId",
        "rtps2.sm.id",
        FT_UINT8,
        BASE_HEX,
        VALS(submessage_id_vals),
        0,
        "defines the type of submessage",
        HFILL }
    },

    /* Submessage flags ---------------------------------------------------- */
    { &hf_rtps_sm_flags, {
        "flags",
        "rtps2.sm.flags",
        FT_UINT8,
        BASE_HEX,
        NULL,
        0,
        "bitmask representing the flags associated with a submessage",
        HFILL }
    },

    /* octets to next header ---------------------------------------------- */
    { &hf_rtps_sm_octets_to_next_header, {
        "octetsToNextHeader",
        "rtps2.sm.octetsToNextHeader",
        FT_UINT16,
        BASE_DEC,
        NULL,
        0,
        "Size of the submessage payload",
        HFILL }
    },

    /* GUID as {GuidPrefix, EntityId} ------------------------------------ */
    { &hf_rtps_sm_guid_prefix, {
        "guidPrefix",
        "rtps2.sm.guidPrefix",
        FT_BYTES,
        BASE_NONE,
        NULL,
        0,
        "a generic guidPrefix that is transmitted inside the submessage (this is NOT the guidPrefix described in the packet header",
        HFILL }
    },

    { &hf_rtps_sm_host_id, {
        "host_id",
        "rtps2.sm.guidPrefix.hostId",
        FT_UINT32,
        BASE_HEX,
        NULL,
        0,
        "The hostId component of the rtps2.sm.guidPrefix",
        HFILL }
    },

    { &hf_rtps_sm_app_id, {
        "appId",
        "rtps2.sm.guidPrefix.appId",
        FT_UINT32,
        BASE_HEX,
        NULL,
        0,
        "AppId component of the rtps2.sm.guidPrefix",
        HFILL }
    },
    { &hf_rtps_sm_instance_id, {
        "instanceId",
        "rtps2.sm.guidPrefix.appId.instanceId",
        FT_UINT24,
        BASE_HEX,
        NULL,
        0,
        "instanceId component of the AppId of the rtps2.sm.guidPrefix",
        HFILL }
    },
    { &hf_rtps_sm_app_kind, {
        "appKind",
        "rtps2.sm.guidPrefix.appId.appKind",
        FT_UINT8,
        BASE_HEX,
        NULL,
        0,
        "appKind component of the AppId of the rtps2.sm.guidPrefix",
        HFILL }
    },

    { &hf_rtps_sm_counter, {
        "counter",
        "rtps2.sm.guidPrefix.counter",
        FT_UINT32,
        BASE_HEX,
        NULL,
        0,
        "The counter component of the rtps2.sm.guidPrefix",
        HFILL }
    },

    /* Entity ID (composed as entityKey, entityKind) ----------------------- */
    { &hf_rtps_sm_entity_id, {
        "entityId",
        "rtps2.sm.entityId",
        FT_UINT32,
        BASE_HEX,
        VALS(entity_id_vals),
        0,
        "Object entity ID as it appears in a DATA submessage (keyHashSuffix)",
        HFILL }
    },
    { &hf_rtps_sm_entity_id_key, {
        "entityKey",
        "rtps2.sm.entityId.entityKey",
        FT_UINT24,
        BASE_HEX,
        NULL,
        0,
        "'entityKey' field of the object entity ID",
        HFILL }
    },
    { &hf_rtps_sm_entity_id_kind, {
        "entityKind",
        "rtps2.sm.entityId.entityKind",
        FT_UINT8,
        BASE_HEX,
        VALS(entity_kind_vals),
        0,
        "'entityKind' field of the object entity ID",
        HFILL }
    },

    { &hf_rtps_sm_rdentity_id, {
        "readerEntityId",
        "rtps2.sm.rdEntityId",
        FT_UINT32,
        BASE_HEX,
        VALS(entity_id_vals),
        0,
        "Reader entity ID as it appears in a submessage",
        HFILL }
    },
    { &hf_rtps_sm_rdentity_id_key, {
        "readerEntityKey",
        "rtps2.sm.rdEntityId.entityKey",
        FT_UINT24,
        BASE_HEX,
        NULL,
        0,
        "'entityKey' field of the reader entity ID",
        HFILL }
    },
    { &hf_rtps_sm_rdentity_id_kind, {
        "readerEntityKind",
        "rtps2.sm.rdEntityId.entityKind",
        FT_UINT8,
        BASE_HEX,
        VALS(entity_kind_vals),
        0,
        "'entityKind' field of the reader entity ID",
        HFILL }
    },

    { &hf_rtps_sm_wrentity_id, {
        "writerEntityId",
        "rtps2.sm.wrEntityId",
        FT_UINT32,
        BASE_HEX,
        VALS(entity_id_vals),
        0,
        "Writer entity ID as it appears in a submessage",
        HFILL }
    },
    { &hf_rtps_sm_wrentity_id_key, {
        "writerEntityKey",
        "rtps2.sm.wrEntityId.entityKey",
        FT_UINT24,
        BASE_HEX,
        NULL,
        0,
        "'entityKey' field of the writer entity ID",
        HFILL }
    },
    { &hf_rtps_sm_wrentity_id_kind, {
        "writerEntityKind",
        "rtps2.sm.wrEntityId.entityKind",
        FT_UINT8,
        BASE_HEX,
        VALS(entity_kind_vals),
        0,
        "'entityKind' field of the writer entity ID",
        HFILL }
    },



    /* Sequence number ----------------------------------------------------- */
    { &hf_rtps_sm_seq_number, {
        "writerSeqNumber",
        "rtps2.sm.seqNumber",
        FT_INT64,
        BASE_DEC,
        NULL,
        0,
        "Writer sequence number",
        HFILL }
    },

    /* Parameter Id -------------------------------------------------------- */
    { &hf_rtps_parameter_id, {
        "parameterId",
        "rtps2.param.id",
        FT_UINT16,
        BASE_HEX,
        VALS(parameter_id_vals),
        0,
        "Parameter Id",
        HFILL }
    },

    /* Parameter Length ---------------------------------------------------- */
    { &hf_rtps_parameter_length, {
        "parameterLength",
        "rtps2.param.length",
        FT_UINT16,
        BASE_DEC,
        NULL,
        0,
        "Parameter Length",
        HFILL }
    },

    /* Parameter / Status Info --------------------------------------------- */
    { &hf_rtps_param_status_info, {
        "statusInfo",
        "rtps2.param.statusInfo",
        FT_UINT32,
        BASE_HEX,
        NULL,
        0,
        "State information of the data object to which the message apply (i.e. lifecycle)",
        HFILL }
    },

    /* Parameter / NtpTime ------------------------------------------------- */
    { &hf_rtps_param_ntpt, {
        "ntpTime",
        "rtps2.param.ntpTime",
        FT_NONE,
        BASE_NONE,
        NULL,
        0,
        "Time using the NTP standard format",
        HFILL }
    },
    { &hf_rtps_param_ntpt_sec, {
        "seconds",
        "rtps2.param.ntpTime.sec",
        FT_INT32,
        BASE_DEC,
        NULL,
        0,
        "The 'second' component of a NTP time",
        HFILL }
    },
    { &hf_rtps_param_ntpt_fraction, {
        "fraction",
        "rtps2.param.ntpTime.fraction",
        FT_UINT32,
        BASE_DEC,
        NULL,
        0,
        "The 'fraction' component of a NTP time",
        HFILL }
    },


    /* Parameter / Topic --------------------------------------------------- */
    { &hf_rtps_param_topic_name, {
        "topic",
        "rtps2.param.topicName",
        FT_STRINGZ,
        BASE_NONE,
        NULL,
        0,
        "String representing the value value of a PID_TOPIC parameter",
        HFILL }
    },

    /* Parameter / Entity -------------------------------------------------- */
    { &hf_rtps_param_entity_name, {
        "entity",
        "rtps2.param.entityName",
        FT_STRINGZ,
        BASE_NONE,
        NULL,
        0,
        "String representing the name of the entity addressed by the submessage",
        HFILL }
    },


    /* Parameter / Strength ------------------------------------------------ */
    { &hf_rtps_param_strength, {
        "strength",
        "rtps2.param.strength",
        FT_INT32,
        BASE_DEC,
        NULL,
        0,
        "Decimal value representing the value of a PID_OWNERSHIP_STRENGTH parameter",
        HFILL }
    },

    /* Parameter / Type Name ----------------------------------------------- */
    { &hf_rtps_param_type_name, {
        "typeName",
        "rtps2.param.typeName",
        FT_STRINGZ,
        BASE_NONE,
        NULL,
        0,
        "String representing the value of a PID_TYPE_NAME parameter",
        HFILL }
    },

    /* Parameter / User Data ----------------------------------------------- */
    { &hf_rtps_param_user_data, {
        "userData",
        "rtps2.param.userData",
        FT_BYTES,
        BASE_NONE,
        NULL,
        0,
        "The user data sent in a PID_USER_DATA parameter",
        HFILL }
    },

    /* Parameter / Group Data ---------------------------------------------- */
    { &hf_rtps_param_group_data, {
        "groupData",
        "rtps2.param.groupData",
        FT_BYTES,
        BASE_NONE,
        NULL,
        0,
        "The user data sent in a PID_GROUP_DATA parameter",
        HFILL }
    },

    /* Parameter / Topic Data ---------------------------------------------- */
    { &hf_rtps_param_topic_data, {
        "topicData",
        "rtps2.param.topicData",
        FT_BYTES,
        BASE_NONE,
        NULL,
        0,
        "The user data sent in a PID_TOPIC_DATA parameter",
        HFILL }
    },


    /* Parameter / Content Filter Name ------------------------------------- */
    { &hf_rtps_param_content_filter_name, {
        "contentFilterName",
        "rtps2.param.contentFilterName",
        FT_STRINGZ,
        BASE_NONE,
        NULL,
        0,
        "Value of the content filter name as sent in a PID_CONTENT_FILTER_PROPERTY parameter",
        HFILL }
    },
    { &hf_rtps_param_related_topic_name, {
        "relatedTopicName",
        "rtps2.param.relatedTopicName",
        FT_STRINGZ,
        BASE_NONE,
        NULL,
        0,
        "Value of the related topic name as sent in a PID_CONTENT_FILTER_PROPERTY parameter",
        HFILL }
    },
    { &hf_rtps_param_filter_name, {
        "filterName",
        "rtps2.param.filterName",
        FT_STRINGZ,
        BASE_NONE,
        NULL,
        0,
        "Value of the filter name as sent in a PID_CONTENT_FILTER_PROPERTY parameter",
        HFILL }
    },

    /* Finally the raw issue data ------------------------------------------ */
    { &hf_rtps_issue_data, {
        "serializedData",
        "rtps2.serializedData",
        FT_BYTES,
        BASE_NONE,
        NULL,
        0,
        "The user data transferred in a ISSUE submessage",
        HFILL }
    },

  };

  static gint *ett[] = {
    &ett_rtps,
    &ett_rtps_default_mapping,
    &ett_rtps_proto_version,
    &ett_rtps_submessage,
    &ett_rtps_parameter_sequence,
    &ett_rtps_parameter,
    &ett_rtps_flags,
    &ett_rtps_entity,
    &ett_rtps_rdentity,
    &ett_rtps_wrentity,
    &ett_rtps_guid_prefix,
    &ett_rtps_part_message_data,
    &ett_rtps_part_message_guid,
    &ett_rtps_locator_udp_v4,
    &ett_rtps_locator,
    &ett_rtps_locator_list,
    &ett_rtps_ntp_time,
    &ett_rtps_bitmap,
    &ett_rtps_seq_string,
    &ett_rtps_seq_ulong,
    &ett_rtps_serialized_data,
    &ett_rtps_sample_info_list,
    &ett_rtps_sample_info,
    &ett_rtps_sample_batch_list,
    &ett_rtps_locator_filter_channel,
    &ett_rtps_locator_filter_locator
  };
  module_t *rtps_module;

  proto_rtps = proto_register_protocol(
                        "Real-Time Publish-Subscribe Wire Protocol 2.x",
                        "RTPS2",
                        "rtps2");
  proto_register_field_array(proto_rtps, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));

  /* Registers the control in the preference panel */
  rtps_module = prefs_register_protocol(proto_rtps, NULL);
  prefs_register_uint_preference(rtps_module, "max_batch_samples_dissected",
            "Max samples dissected for DATA_BATCH",
            "Specifies the maximum number of samples dissected in "
            "a DATA_BATCH submessage. Increasing this value may affect "
            "performances if the trace has a lot of big batched samples.",
            10, &rtps_max_batch_samples_dissected);
}

void proto_reg_handoff_rtps2(void) {
  heur_dissector_add("udp", dissect_rtps, proto_rtps);
}

