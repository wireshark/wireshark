/* packet-rtps.c
 * ~~~~~~~~~~~~~
 *
 * Routines for Real-Time Publish-Subscribe Protocol (RTPS) dissection
 *
 * Copyright 2005, Fabrizio Bertocci <fabrizio@rti.com>
 * Real-Time Innovations, Inc.
 * 385 Moffett Park Drive
 * Sunnyvale, CA 94089
 *
 * Copyright 2003, LUKAS POKORNY <maskis@seznam.cz>
 *                 PETR SMOLIK   <petr.smolik@wo.cz>
 *                 ZDENEK SEBEK  <sebek@fel.cvut.cz>
 * Czech Technical University in Prague
 *  Faculty of Electrical Engineering <www.fel.cvut.cz>
 *  Department of Control Engineering <dce.felk.cvut.cz>
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 *                  -------------------------------------
 *
 * The following file is part of the RTPS packet dissector for Wireshark.
 *
 * RTPS protocol was developed by Real-Time Innovations, Inc. as wire
 * protocol for Data Distribution System.
 * Additional information at:
 *   Full OMG DDS Standard Specification:
 *                             http://www.omg.org/cgi-bin/doc?ptc/2003-07-07
 *
 *   NDDS and RTPS information: http://www.rti.com/resources.html
 *
 */


#include "config.h"

#include <glib.h>
#include <epan/packet.h>
#include <epan/expert.h>
#include <epan/prefs.h>
#include <epan/addr_resolv.h>
#include <epan/wmem/wmem.h>

#include "packet-rtps.h"

void proto_register_rtps(void);
void proto_reg_handoff_rtps(void);

static const char * const SM_EXTRA_RPLUS  = "(r+)";
static const char * const SM_EXTRA_RMINUS = "(r-)";
static const char * const SM_EXTRA_WPLUS  = "(w+)";
static const char * const SM_EXTRA_WMINUS = "(w-)";
static const char * const SM_EXTRA_PPLUS  = "(p+)";
static const char * const SM_EXTRA_PMINUS = "(p-)";
static const char * const SM_EXTRA_TPLUS  = "(t+)";
static const char * const SM_EXTRA_TMINUS = "(t-)";

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
static int hf_rtps_app_id_instance_id           = -1;
static int hf_rtps_app_id_app_kind              = -1;

static int hf_rtps_sm_id                        = -1;
static int hf_rtps_sm_idv2                      = -1;
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

static int hf_rtps_info_src_ip                  = -1;
static int hf_rtps_info_src_unused              = -1;

static int hf_rtps_parameter_id                 = -1;
static int hf_rtps_parameter_id_v2              = -1;
static int hf_rtps_parameter_length             = -1;
static int hf_rtps_param_topic_name             = -1;
static int hf_rtps_param_strength               = -1;
static int hf_rtps_param_type_name              = -1;
static int hf_rtps_param_user_data              = -1;
static int hf_rtps_param_group_data             = -1;
static int hf_rtps_param_topic_data             = -1;
static int hf_rtps_param_content_filter_name    = -1;
static int hf_rtps_param_related_topic_name     = -1;
static int hf_rtps_param_filter_name            = -1;
static int hf_rtps_issue_data                   = -1;
static int hf_rtps_durability_service_cleanup_delay = -1;
static int hf_rtps_liveliness_lease_duration    = -1;
static int hf_rtps_participant_lease_duration   = -1;
static int hf_rtps_time_based_filter_minimum_separation = -1;
static int hf_rtps_reliability_max_blocking_time= -1;
static int hf_rtps_deadline_period              = -1;
static int hf_rtps_latency_budget_duration      = -1;
static int hf_rtps_lifespan_duration            = -1;
static int hf_rtps_persistence                  = -1;
static int hf_rtps_info_ts_timestamp            = -1;
static int hf_rtps_locator_kind                 = -1;
static int hf_rtps_locator_port                 = -1;
static int hf_rtps_locator_ipv4                 = -1;
static int hf_rtps_locator_ipv6                 = -1;
static int hf_rtps_participant_builtin_endpoints= -1;
static int hf_rtps_participant_manual_liveliness_count = -1;
static int hf_rtps_history_depth                = -1;
static int hf_rtps_resource_limit_max_samples   = -1;
static int hf_rtps_resource_limit_max_instances = -1;
static int hf_rtps_resource_limit_max_samples_per_instances = -1;
static int hf_rtps_filter_bitmap                = -1;
static int hf_rtps_type_checksum                = -1;
static int hf_rtps_queue_size                   = -1;
static int hf_rtps_acknack_counter              = -1;
static int hf_rtps_durability_service_history_kind = -1;
static int hf_rtps_durability_service_history_depth = -1;
static int hf_rtps_durability_service_max_samples = -1;
static int hf_rtps_durability_service_max_instances = -1;
static int hf_rtps_durability_service_max_samples_per_instances = -1;
static int hf_rtps_liveliness_kind              = -1;
static int hf_rtps_manager_key                  = -1;
static int hf_rtps_locator_udp_v4               = -1;
static int hf_rtps_locator_udp_v4_port          = -1;
static int hf_param_ip_address                  = -1;
static int hf_rtps_param_port                   = -1;
static int hf_rtps_expects_inline_qos           = -1;
static int hf_rtps_presentation_coherent_access = -1;
static int hf_rtps_presentation_ordered_access  = -1;
static int hf_rtps_expects_ack                  = -1;
static int hf_rtps_reliability_kind             = -1;
static int hf_rtps_durability                   = -1;
static int hf_rtps_ownership                    = -1;
static int hf_rtps_presentation_access_scope    = -1;
static int hf_rtps_destination_order            = -1;
static int hf_rtps_history_kind                 = -1;
static int hf_rtps_data_status_info             = -1;
static int hf_rtps_param_serialize_encap_kind   = -1;
static int hf_rtps_param_serialize_encap_len    = -1;
static int hf_rtps_param_status_info            = -1;
static int hf_rtps_param_transport_priority     = -1;
static int hf_rtps_param_type_max_size_serialized = -1;
static int hf_rtps_param_entity_name            = -1;
static int hf_rtps_disable_positive_ack         = -1;
static int hf_rtps_participant_guid             = -1;
static int hf_rtps_group_guid                   = -1;
static int hf_rtps_endpoint_guid                = -1;
static int hf_rtps_param_host_id                = -1;
static int hf_rtps_param_app_id                 = -1;
static int hf_rtps_param_instance_id            = -1;
static int hf_rtps_param_app_kind               = -1;
static int hf_rtps_param_entity                 = -1;
static int hf_rtps_param_entity_key             = -1;
static int hf_rtps_param_hf_entity_kind         = -1;
static int hf_rtps_param_counter                = -1;
static int hf_rtps_data_frag_number             = -1;
static int hf_rtps_data_frag_num_fragments      = -1;
static int hf_rtps_data_frag_size               = -1;
static int hf_rtps_data_frag_sample_size        = -1;
static int hf_rtps_nokey_data_frag_number       = -1;
static int hf_rtps_nokey_data_frag_num_fragments= -1;
static int hf_rtps_nokey_data_frag_size         = -1;
static int hf_rtps_nack_frag_count              = -1;
static int hf_rtps_heartbeat_frag_number        = -1;
static int hf_rtps_heartbeat_frag_count         = -1;
static int hf_rtps_heartbeat_batch_count        = -1;
static int hf_rtps_data_serialize_data          = -1;
static int hf_rtps_data_batch_timestamp         = -1;
static int hf_rtps_data_batch_offset_to_last_sample_sn = -1;
static int hf_rtps_data_batch_sample_count      = -1;
static int hf_rtps_data_batch_offset_sn         = -1;
static int hf_rtps_data_batch_octets_to_sl_encap_id = -1;
static int hf_rtps_data_batch_serialized_data_length = -1;
static int hf_rtps_data_batch_octets_to_inline_qos = -1;
static int hf_rtps_fragment_number_base64       = -1;
static int hf_rtps_fragment_number_base         = -1;
static int hf_rtps_fragment_number_num_bits     = -1;
static int hf_rtps_bitmap_num_bits              = -1;
static int hf_rtps_param_partition_num          = -1;
static int hf_rtps_param_partition              = -1;
static int hf_rtps_param_filter_expression      = -1;
static int hf_rtps_param_filter_parameters_num  = -1;
static int hf_rtps_param_filter_parameters      = -1;
static int hf_rtps_locator_filter_list_num_channels = -1;
static int hf_rtps_locator_filter_list_filter_name = -1;
static int hf_rtps_locator_filter_list_filter_exp = -1;
static int hf_rtps_extra_flags                  = -1;
static int hf_rtps_param_builtin_endpoint_set   = -1;
static int hf_rtps_param_plugin_promiscuity_kind = -1;
static int hf_rtps_param_service_kind           = -1;


/* Subtree identifiers */
static gint ett_rtps                            = -1;
static gint ett_rtps_default_mapping            = -1;
static gint ett_rtps_proto_version              = -1;
static gint ett_rtps_submessage                 = -1;
static gint ett_rtps_parameter_sequence         = -1;
static gint ett_rtps_parameter                  = -1;
static gint ett_rtps_flags                      = -1;
static gint ett_rtps_entity                     = -1;
static gint ett_rtps_generic_guid               = -1;
static gint ett_rtps_rdentity                   = -1;
static gint ett_rtps_wrentity                   = -1;
static gint ett_rtps_guid_prefix                = -1;
static gint ett_rtps_app_id                     = -1;
static gint ett_rtps_locator_udp_v4             = -1;
static gint ett_rtps_locator                    = -1;
static gint ett_rtps_locator_list               = -1;
static gint ett_rtps_ntp_time                   = -1;
static gint ett_rtps_bitmap                     = -1;
static gint ett_rtps_seq_string                 = -1;
static gint ett_rtps_seq_ulong                  = -1;
static gint ett_rtps_resource_limit             = -1;
static gint ett_rtps_durability_service         = -1;
static gint ett_rtps_liveliness                 = -1;
static gint ett_rtps_manager_key                = -1;
static gint ett_rtps_serialized_data            = -1;
static gint ett_rtps_locator_filter_channel     = -1;
static gint ett_rtps_part_message_data          = -1;
static gint ett_rtps_sample_info_list           = -1;
static gint ett_rtps_sample_info                = -1;
static gint ett_rtps_sample_batch_list          = -1;

static expert_field ei_rtps_sm_octets_to_next_header_error = EI_INIT;
static expert_field ei_rtps_port_invalid = EI_INIT;
static expert_field ei_rtps_ip_invalid = EI_INIT;
static expert_field ei_rtps_parameter_value_invalid = EI_INIT;
static expert_field ei_rtps_extra_bytes = EI_INIT;
static expert_field ei_rtps_missing_bytes = EI_INIT;
static expert_field ei_rtps_locator_port = EI_INIT;
static expert_field ei_rtps_more_samples_available = EI_INIT;
static expert_field ei_rtps_parameter_not_decoded = EI_INIT;
static expert_field ei_rtps_sm_octets_to_next_header_not_zero = EI_INIT;

/***************************************************************************/
/* Preferences                                                             */
/***************************************************************************/
static guint rtps_max_batch_samples_dissected = 16;

/***************************************************************************/
/* Value-to-String Tables */
static const value_string vendor_vals[] = {
  { RTPS_VENDOR_UNKNOWN,       RTPS_VENDOR_UNKNOWN_STRING},
  { RTPS_VENDOR_RTI_DDS,       RTPS_VENDOR_RTI_DDS_STRING},
  { RTPS_VENDOR_PT_DDS,        RTPS_VENDOR_PT_DDS_STRING},
  { RTPS_VENDOR_OCI,           RTPS_VENDOR_OCI_STRING},
  { RTPS_VENDOR_MILSOFT,       RTPS_VENDOR_MILSOFT_STRING},
  { RTPS_VENDOR_GALLIUM,       RTPS_VENDOR_GALLIUM_STRING},
  { RTPS_VENDOR_TOC,           RTPS_VENDOR_TOC_STRING},
  { RTPS_VENDOR_LAKOTA_TSI,    RTPS_VENDOR_LAKOTA_TSI_STRING},
  { RTPS_VENDOR_ICOUP,         RTPS_VENDOR_ICOUP_STRING},
  { RTPS_VENDOR_ETRI,          RTPS_VENDOR_ETRI_STRING},
  { RTPS_VENDOR_RTI_DDS_MICRO, RTPS_VENDOR_RTI_DDS_MICRO_STRING},
  { RTPS_VENDOR_PT_MOBILE,     RTPS_VENDOR_PT_MOBILE_STRING},
  { RTPS_VENDOR_PT_GATEWAY,    RTPS_VENDOR_PT_GATEWAY_STRING},
  { RTPS_VENDOR_PT_LITE,       RTPS_VENDOR_PT_LITE_STRING},
  { RTPS_VENDOR_TECHNICOLOR,   RTPS_VENDOR_TECHNICOLOR_STRING},
  { 0, NULL }
};

static const value_string entity_id_vals[] = {
  { ENTITYID_UNKNOWN,                           "ENTITYID_UNKNOWN" },
  { ENTITYID_BUILTIN_TOPIC_WRITER,              "ENTITYID_BUILTIN_TOPIC_WRITER" },
  { ENTITYID_BUILTIN_TOPIC_READER,              "ENTITYID_BUILTIN_TOPIC_READER" },
  { ENTITYID_BUILTIN_PUBLICATIONS_WRITER,       "ENTITYID_BUILTIN_PUBLICATIONS_WRITER" },
  { ENTITYID_BUILTIN_PUBLICATIONS_READER,       "ENTITYID_BUILTIN_PUBLICATIONS_READER" },
  { ENTITYID_BUILTIN_SUBSCRIPTIONS_WRITER,      "ENTITYID_BUILTIN_SUBSCRIPTIONS_WRITER" },
  { ENTITYID_BUILTIN_SUBSCRIPTIONS_READER,      "ENTITYID_BUILTIN_SUBSCRIPTIONS_READER" },
  { ENTITYID_BUILTIN_SDP_PARTICIPANT_WRITER,    "ENTITYID_BUILTIN_SDP_PARTICIPANT_WRITER" },
  { ENTITYID_BUILTIN_SDP_PARTICIPANT_READER,    "ENTITYID_BUILTIN_SDP_PARTICIPANT_READER" },

  /* Deprecated Items */
  { ENTITYID_APPLICATIONS_WRITER,               "writerApplications [DEPRECATED]" },
  { ENTITYID_APPLICATIONS_READER,               "readerApplications [DEPRECATED]" },
  { ENTITYID_CLIENTS_WRITER,                    "writerClients [DEPRECATED]" },
  { ENTITYID_CLIENTS_READER,                    "readerClients [DEPRECATED]" },
  { ENTITYID_SERVICES_WRITER,                   "writerServices [DEPRECATED]" },
  { ENTITYID_SERVICES_READER,                   "readerServices [DEPRECATED]" },
  { ENTITYID_MANAGERS_WRITER,                   "writerManagers [DEPRECATED]" },
  { ENTITYID_MANAGERS_READER,                   "readerManagers [DEPRECATED]" },
  { ENTITYID_APPLICATION_SELF,                  "applicationSelf [DEPRECATED]" },
  { ENTITYID_APPLICATION_SELF_WRITER,           "writerApplicationSelf [DEPRECATED]" },
  { ENTITYID_APPLICATION_SELF_READER,           "readerApplicationSelf [DEPRECATED]" },
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

static const value_string rtps_locator_kind_vals[] = {
  { LOCATOR_KIND_UDPV4,        "LOCATOR_KIND_UDPV4" },
  { LOCATOR_KIND_UDPV6,        "LOCATOR_KIND_UDPV6" },
  { LOCATOR_KIND_INVALID,      "LOCATOR_KIND_INVALID" },
  { LOCATOR_KIND_RESERVED,     "LOCATOR_KIND_RESERVED" },
  { 0, NULL }
};

static const value_string submessage_id_vals[] = {
  { SUBMESSAGE_PAD,               "PAD" },
  { SUBMESSAGE_DATA,              "DATA" },
  { SUBMESSAGE_NOKEY_DATA,        "NOKEY_DATA" },
  { SUBMESSAGE_ACKNACK,           "ACKNACK" },
  { SUBMESSAGE_HEARTBEAT,         "HEARTBEAT" },
  { SUBMESSAGE_GAP,               "GAP" },
  { SUBMESSAGE_INFO_TS,           "INFO_TS" },
  { SUBMESSAGE_INFO_SRC,          "INFO_SRC" },
  { SUBMESSAGE_INFO_REPLY_IP4,    "INFO_REPLY_IP4" },
  { SUBMESSAGE_INFO_DST,          "INFO_DST" },
  { SUBMESSAGE_INFO_REPLY,        "INFO_REPLY" },
  { 0, NULL }
};

static const value_string submessage_id_valsv2[] = {
  { SUBMESSAGE_PAD,               "PAD" },
  { SUBMESSAGE_RTPS_DATA,         "DATA" },
  { SUBMESSAGE_RTPS_DATA_FRAG,    "DATA_FRAG" },
  { SUBMESSAGE_RTPS_DATA_BATCH,   "DATA_BATCH" },
  { SUBMESSAGE_ACKNACK,           "ACKNACK" },
  { SUBMESSAGE_HEARTBEAT,         "HEARTBEAT" },
  { SUBMESSAGE_GAP,               "GAP" },
  { SUBMESSAGE_INFO_TS,           "INFO_TS" },
  { SUBMESSAGE_INFO_SRC,          "INFO_SRC" },
  { SUBMESSAGE_INFO_REPLY_IP4,    "INFO_REPLY_IP4" },
  { SUBMESSAGE_INFO_DST,          "INFO_DST" },
  { SUBMESSAGE_INFO_REPLY,        "INFO_REPLY" },
  { SUBMESSAGE_NACK_FRAG,         "NACK_FRAG" },
  { SUBMESSAGE_HEARTBEAT_FRAG,    "HEARTBEAT_FRAG" },
  { SUBMESSAGE_ACKNACK_BATCH,     "ACKNACK_BATCH" },
  { SUBMESSAGE_HEARTBEAT_BATCH,   "HEARTBEAT_BATCH" },
  { SUBMESSAGE_ACKNACK_SESSION,   "ACKNACK_SESSION" },
  { SUBMESSAGE_HEARTBEAT_SESSION, "HEARTBEAT_SESSION" },
  { SUBMESSAGE_RTPS_DATA_SESSION, "DATA_SESSION" },
  /* Deprecated submessages */
  { SUBMESSAGE_DATA,              "DATA_deprecated" },
  { SUBMESSAGE_NOKEY_DATA,        "NOKEY_DATA_deprecated" },
  { SUBMESSAGE_DATA_FRAG,         "DATA_FRAG_deprecated" },
  { SUBMESSAGE_NOKEY_DATA_FRAG,   "NOKEY_DATA_FRAG_deprecated" },
  { 0, NULL }
};


#if 0
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
#endif

static const value_string parameter_id_vals[] = {
  { PID_PAD,                            "PID_PAD" },
  { PID_SENTINEL,                       "PID_SENTINEL" },
  { PID_USER_DATA,                      "PID_USER_DATA" },
  { PID_TOPIC_NAME,                     "PID_TOPIC_NAME" },
  { PID_TYPE_NAME,                      "PID_TYPE_NAME" },
  { PID_GROUP_DATA,                     "PID_GROUP_DATA" },
  { PID_DEADLINE,                       "PID_DEADLINE" },
  { PID_DEADLINE_OFFERED,               "PID_DEADLINE_OFFERED [deprecated]" },
  { PID_PARTICIPANT_LEASE_DURATION,     "PID_PARTICIPANT_LEASE_DURATION" },
  { PID_PERSISTENCE,                    "PID_PERSISTENCE" },
  { PID_TIME_BASED_FILTER,              "PID_TIME_BASED_FILTER" },
  { PID_OWNERSHIP_STRENGTH,             "PID_OWNERSHIP_STRENGTH" },
  { PID_TYPE_CHECKSUM,                  "PID_TYPE_CHECKSUM [deprecated]" },
  { PID_TYPE2_NAME,                     "PID_TYPE2_NAME [deprecated]" },
  { PID_TYPE2_CHECKSUM,                 "PID_TYPE2_CHECKSUM [deprecated]" },
  { PID_METATRAFFIC_MULTICAST_IPADDRESS,"PID_METATRAFFIC_MULTICAST_IPADDRESS"},
  { PID_DEFAULT_UNICAST_IPADDRESS,      "PID_DEFAULT_UNICAST_IPADDRESS" },
  { PID_METATRAFFIC_UNICAST_PORT,       "PID_METATRAFFIC_UNICAST_PORT" },
  { PID_DEFAULT_UNICAST_PORT,           "PID_DEFAULT_UNICAST_PORT" },
  { PID_IS_RELIABLE,                    "PID_IS_RELIABLE [deprecated]" },
  { PID_EXPECTS_ACK,                    "PID_EXPECTS_ACK" },
  { PID_MULTICAST_IPADDRESS,            "PID_MULTICAST_IPADDRESS" },
  { PID_MANAGER_KEY,                    "PID_MANAGER_KEY [deprecated]" },
  { PID_SEND_QUEUE_SIZE,                "PID_SEND_QUEUE_SIZE" },
  { PID_RELIABILITY_ENABLED,            "PID_RELIABILITY_ENABLED" },
  { PID_PROTOCOL_VERSION,               "PID_PROTOCOL_VERSION" },
  { PID_VENDOR_ID,                      "PID_VENDOR_ID" },
  { PID_VARGAPPS_SEQUENCE_NUMBER_LAST,  "PID_VARGAPPS_SEQUENCE_NUMBER_LAST [deprecated]" },
  { PID_RECV_QUEUE_SIZE,                "PID_RECV_QUEUE_SIZE [deprecated]" },
  { PID_RELIABILITY_OFFERED,            "PID_RELIABILITY_OFFERED [deprecated]" },
  { PID_RELIABILITY,                    "PID_RELIABILITY" },
  { PID_LIVELINESS,                     "PID_LIVELINESS" },
  { PID_LIVELINESS_OFFERED,             "PID_LIVELINESS_OFFERED [deprecated]" },
  { PID_DURABILITY,                     "PID_DURABILITY" },
  { PID_DURABILITY_SERVICE,             "PID_DURABILITY_SERVICE" },
  { PID_PRESENTATION_OFFERED,           "PID_PRESENTATION_OFFERED [deprecated]" },
  { PID_OWNERSHIP,                      "PID_OWNERSHIP" },
  { PID_OWNERSHIP_OFFERED,              "PID_OWNERSHIP_OFFERED [deprecated]" },
  { PID_PRESENTATION,                   "PID_PRESENTATION" },
  { PID_DESTINATION_ORDER,              "PID_DESTINATION_ORDER" },
  { PID_DESTINATION_ORDER_OFFERED,      "PID_DESTINATION_ORDER_OFFERED [deprecated]" },
  { PID_LATENCY_BUDGET,                 "PID_LATENCY_BUDGET" },
  { PID_LATENCY_BUDGET_OFFERED,         "PID_LATENCY_BUDGET_OFFERED [deprecated]" },
  { PID_PARTITION,                      "PID_PARTITION" },
  { PID_PARTITION_OFFERED,              "PID_PARTITION_OFFERED [deprecated]" },
  { PID_LIFESPAN,                       "PID_LIFESPAN" },
  { PID_TOPIC_DATA,                     "PID_TOPIC_DATA" },
  { PID_UNICAST_LOCATOR,                "PID_UNICAST_LOCATOR" },
  { PID_MULTICAST_LOCATOR,              "PID_MULTICAST_LOCATOR" },
  { PID_DEFAULT_UNICAST_LOCATOR,        "PID_DEFAULT_UNICAST_LOCATOR" },
  { PID_METATRAFFIC_UNICAST_LOCATOR,    "PID_METATRAFFIC_UNICAST_LOCATOR " },
  { PID_METATRAFFIC_MULTICAST_LOCATOR,  "PID_METATRAFFIC_MULTICAST_LOCATOR" },
  { PID_PARTICIPANT_MANUAL_LIVELINESS_COUNT, "PID_PARTICIPANT_MANUAL_LIVELINESS_COUNT" },
  { PID_HISTORY,                        "PID_HISTORY" },
  { PID_RESOURCE_LIMIT,                 "PID_RESOURCE_LIMIT" },
  { PID_METATRAFFIC_MULTICAST_PORT,     "PID_METATRAFFIC_MULTICAST_PORT" },
  { PID_EXPECTS_INLINE_QOS,             "PID_EXPECTS_INLINE_QOS" },
  { PID_METATRAFFIC_UNICAST_IPADDRESS,  "PID_METATRAFFIC_UNICAST_IPADDRESS" },
  { PID_PARTICIPANT_BUILTIN_ENDPOINTS,  "PID_PARTICIPANT_BUILTIN_ENDPOINTS" },
  { PID_CONTENT_FILTER_PROPERTY,        "PID_CONTENT_FILTER_PROPERTY" },
  { PID_PROPERTY_LIST_OLD,              "PID_PROPERTY_LIST" },
  { PID_FILTER_SIGNATURE,               "PID_FILTER_SIGNATURE" },
  { PID_COHERENT_SET,                   "PID_COHERENT_SET" },
  { PID_TYPECODE,                       "PID_TYPECODE" },
  { PID_PARTICIPANT_GUID,               "PID_PARTICIPANT_GUID" },
  { PID_PARTICIPANT_ENTITY_ID,          "PID_PARTICIPANT_ENTITY_ID" },
  { PID_GROUP_GUID,                     "PID_GROUP_GUID" },
  { PID_GROUP_ENTITY_ID,                "PID_GROUP_ENTITY_ID" },
  { 0, NULL }
};

static const value_string parameter_id_v2_vals[] = {
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
  { PID_TYPECODE_RTPS2,                 "PID_TYPECODE" },
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

static const struct Flag_definition DATA_FLAGSv1[] = {
  { RESERVEDFLAG_CHAR, RESERVEDFLAG_STRING },   /* Bit 7 */
  { RESERVEDFLAG_CHAR, RESERVEDFLAG_STRING },   /* Bit 6 */
  { 'U', "Unregister flag" },                   /* Bit 5 */
  { 'Q', "Inline QoS" },                        /* Bit 4 */
  { 'H', "Hash key flag" },                     /* Bit 3 */
  { 'A', "Alive flag" },                        /* Bit 2 */
  { 'D', "Data present" },                      /* Bit 1 */
  { 'E', "Endianness bit" }                     /* Bit 0 */
};

static const struct Flag_definition DATA_FLAGSv2[] = {
  { RESERVEDFLAG_CHAR, RESERVEDFLAG_STRING },   /* Bit 7 */
  { RESERVEDFLAG_CHAR, RESERVEDFLAG_STRING },   /* Bit 6 */
  { RESERVEDFLAG_CHAR, RESERVEDFLAG_STRING },   /* Bit 5 */
  { 'I', "Status info flag" },                  /* Bit 4 */
  { 'H', "Hash key flag" },                     /* Bit 3 */
  { 'D', "Data present" },                      /* Bit 2 */
  { 'Q', "Inline QoS" },                        /* Bit 1 */
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

static const struct Flag_definition NOKEY_DATA_FLAGS[] = {
  { RESERVEDFLAG_CHAR, RESERVEDFLAG_STRING },   /* Bit 7 */
  { RESERVEDFLAG_CHAR, RESERVEDFLAG_STRING },   /* Bit 6 */
  { RESERVEDFLAG_CHAR, RESERVEDFLAG_STRING },   /* Bit 5 */
  { RESERVEDFLAG_CHAR, RESERVEDFLAG_STRING },   /* Bit 4 */
  { RESERVEDFLAG_CHAR, RESERVEDFLAG_STRING },   /* Bit 3 */
  { RESERVEDFLAG_CHAR, RESERVEDFLAG_STRING },   /* Bit 2 */
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

static const struct Flag_definition INFO_TS_FLAGS[] = {
  { RESERVEDFLAG_CHAR, RESERVEDFLAG_STRING },   /* Bit 7 */
  { RESERVEDFLAG_CHAR, RESERVEDFLAG_STRING },   /* Bit 6 */
  { RESERVEDFLAG_CHAR, RESERVEDFLAG_STRING },   /* Bit 5 */
  { RESERVEDFLAG_CHAR, RESERVEDFLAG_STRING },   /* Bit 4 */
  { RESERVEDFLAG_CHAR, RESERVEDFLAG_STRING },   /* Bit 3 */
  { RESERVEDFLAG_CHAR, RESERVEDFLAG_STRING },   /* Bit 2 */
  { 'T', "Timestamp flag" },                    /* Bit 1 */
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


/***************************************************************************/
/* Inline macros */

#define NEXT_guint16(tvb, offset, le)    \
                (le ? tvb_get_letohs(tvb, offset) : tvb_get_ntohs(tvb, offset))

#define NEXT_guint32(tvb, offset, le)    \
                (le ? tvb_get_letohl(tvb, offset) : tvb_get_ntohl(tvb, offset))


/* *********************************************************************** */
/* Appends extra formatting for those submessages that have a status info
 */
static void info_summary_append_ex(packet_info *pinfo,
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

  switch(writer_id)
  {
  case ENTITYID_PARTICIPANT:
    buffer[1] = 'P';
    break;
  case ENTITYID_BUILTIN_TOPIC_WRITER:
    buffer[1] = 't';
    break;
  case ENTITYID_BUILTIN_PUBLICATIONS_WRITER:
    buffer[1] = 'w';
    break;
  case ENTITYID_BUILTIN_SUBSCRIPTIONS_WRITER:
    buffer[1] = 'r';
    break;
  case ENTITYID_BUILTIN_SDP_PARTICIPANT_WRITER:
    buffer[1] = 'p';
    break;
  case ENTITYID_P2P_BUILTIN_PARTICIPANT_MESSAGE_WRITER:
    buffer[1] = 'm';
    break;
  default:
    /* Unknown writer ID, don't format anything */
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
  col_append_str(pinfo->cinfo, COL_INFO, buffer);
}

/* *********************************************************************** */
guint16 rtps_util_add_protocol_version(proto_tree *tree, /* Can NOT be NULL */
                        tvbuff_t *  tvb,
                        gint        offset) {
  proto_item * ti;
  proto_tree * version_tree;
  guint16 version;

  version = tvb_get_ntohs(tvb, offset);

  ti = proto_tree_add_uint_format(tree, hf_rtps_protocol_version, tvb, offset, 2,
                        version, "Protocol version: %d.%d",
                        tvb_get_guint8(tvb, offset), tvb_get_guint8(tvb, offset+1));
  version_tree = proto_item_add_subtree(ti, ett_rtps_proto_version);

  proto_tree_add_item(version_tree, hf_rtps_protocol_version_major, tvb, offset, 1, ENC_NA);
  proto_tree_add_item(version_tree, hf_rtps_protocol_version_minor, tvb, offset+1, 1, ENC_NA);

  return version;
}


/* ------------------------------------------------------------------------- */
/* Interpret the next bytes as vendor ID. If proto_tree and field ID is
 * provided, it can also set.
 */
guint16 rtps_util_add_vendor_id(proto_tree *tree,
                        tvbuff_t * tvb,
                        gint       offset) {
  guint8 major, minor;
  guint16 vendor_id;

  major = tvb_get_guint8(tvb, offset);
  minor = tvb_get_guint8(tvb, offset+1);
  vendor_id = tvb_get_ntohs(tvb, offset);

  proto_tree_add_uint_format_value(tree, hf_rtps_vendor_id, tvb, offset, 2, vendor_id,
                        "%02d.%02d (%s)", major, minor,
                        val_to_str_const(vendor_id, vendor_vals, "Unknown"));

  return vendor_id;
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
void rtps_util_add_locator_t(proto_tree *tree, packet_info *pinfo, tvbuff_t * tvb, gint offset,
                             gboolean little_endian, const guint8 * label) {

  proto_item * ti;
  proto_tree * locator_tree;
  gint32  kind;
  guint32 port;

  ti = proto_tree_add_text(tree, tvb, offset, 24, "%s", label);
  locator_tree = proto_item_add_subtree(ti, ett_rtps_locator);

  kind = NEXT_guint32(tvb, offset, little_endian);
  port = NEXT_guint32(tvb, offset+4, little_endian);

  proto_tree_add_uint(locator_tree, hf_rtps_locator_kind, tvb, offset, 4, kind);
  ti = proto_tree_add_int(locator_tree, hf_rtps_locator_port, tvb, offset+4, 4, port);
  if (port == 0)
    expert_add_info(pinfo, ti, &ei_rtps_locator_port);

  if (kind == LOCATOR_KIND_UDPV4) {
    proto_tree_add_item(locator_tree, hf_rtps_locator_ipv4, tvb, offset+20, 4, ENC_BIG_ENDIAN);
  } else {
    proto_tree_add_item(locator_tree, hf_rtps_locator_ipv6, tvb, offset+8, 16, ENC_NA);
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
int rtps_util_add_locator_list(proto_tree *tree, packet_info *pinfo, tvbuff_t * tvb,
                                gint offset, const guint8* label, gboolean little_endian) {

  proto_item *ti;
  proto_tree *locator_tree;
  guint32 num_locators;

  num_locators = NEXT_guint32(tvb, offset, little_endian);
  if (tree) {
    ti = proto_tree_add_text(tree, tvb, offset, 4,
                        "%s: %d Locators", label, num_locators);
  } else {
    return offset + 4 + ((num_locators > 0) ? (24 * num_locators) : 0);
  }
  offset += 4;
  if (num_locators > 0) {
    guint32 i;
    char temp_buff[20];

    locator_tree = proto_item_add_subtree(ti, ett_rtps_locator_udp_v4);

    for (i = 0; i < num_locators; ++i) {
      g_snprintf(temp_buff, 20, "Locator[%d]", i);
      rtps_util_add_locator_t(locator_tree, pinfo, tvb, offset,
                        little_endian, temp_buff);
      offset += 24;
    }
  }
  return offset;
}


/* ------------------------------------------------------------------------- */
/* Insert in the protocol tree the next 4 bytes interpreted as IPV4Address_t
 */
void rtps_util_add_ipv4_address_t(proto_tree *tree, packet_info *pinfo, tvbuff_t * tvb, gint offset,
                                  gboolean little_endian, int hf_item) {

  guint32 addr;
  proto_item* ti;

  addr = NEXT_guint32(tvb, offset, little_endian);

  ti = proto_tree_add_ipv4(tree, hf_item, tvb, offset, 4, addr);
  if (addr == IPADDRESS_INVALID)
    expert_add_info(pinfo, ti, &ei_rtps_ip_invalid);
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
void rtps_util_add_locator_udp_v4(proto_tree *tree, packet_info *pinfo, tvbuff_t * tvb,
                                  gint offset, const guint8 * label, gboolean little_endian) {

  proto_item * ti;
  proto_tree * locator_tree;
  guint32 port;

  ti = proto_tree_add_text(tree, tvb, offset, 8, "%s", label);
  locator_tree = proto_item_add_subtree(ti, ett_rtps_locator_udp_v4);

  rtps_util_add_ipv4_address_t(locator_tree, pinfo, tvb, offset,
                               little_endian, hf_rtps_locator_udp_v4);

  port = NEXT_guint32(tvb, offset+4, little_endian);
  ti = proto_tree_add_uint(locator_tree, hf_rtps_locator_udp_v4_port, tvb, offset, 4, port);
  if (port == PORT_INVALID)
    expert_add_info(pinfo, ti, &ei_rtps_port_invalid);
}


/* ------------------------------------------------------------------------- */
/* Insert in the protocol tree the next 8 bytes interpreted as GuidPrefix
 * If tree is specified, it fills up the protocol tree item:
 *  - hf_rtps_guid_prefix
 *  - hf_rtps_host_id
 *  - hf_rtps_app_id
 *  - hf_rtps_app_id_instance_id
 *  - hf_rtps_app_id_app_kind
 */
static void rtps_util_add_guid_prefix_v1(proto_tree *tree, tvbuff_t *tvb, gint offset,
                        int hf_prefix, int hf_host_id, int hf_app_id, int hf_app_id_instance_id,
                        int hf_app_id_app_kind, const guint8 * label) {
  guint64 prefix;
  guint32  host_id, app_id, instance_id;
  guint8   app_kind;
  proto_item *ti;
  proto_tree *guid_tree, *appid_tree;
  const guint8 * safe_label = (label == NULL) ? (const guint8 *)"guidPrefix" : label;

  /* Read values from TVB */
  prefix = tvb_get_ntoh64(tvb, offset);
  host_id   = tvb_get_ntohl(tvb, offset);
  app_id    = tvb_get_ntohl(tvb, offset + 4);
  instance_id = (app_id >> 8);
  app_kind    = (app_id & 0xff);

  if (tree != NULL) {
    ti = proto_tree_add_uint64_format(tree, hf_prefix, tvb, offset, 8, prefix,
                        "%s=%08x %08x { hostId=%08x, appId=%08x (%s: %06x) }",
                        safe_label, host_id, app_id, host_id, app_id,
                        val_to_str(app_kind, app_kind_vals, "%02x"),
                        instance_id);

    guid_tree = proto_item_add_subtree(ti, ett_rtps_guid_prefix);

    /* Host Id */
    proto_tree_add_item(guid_tree, hf_host_id, tvb, offset, 4, ENC_BIG_ENDIAN);

    /* AppId (root of the app_id sub-tree) */
    ti = proto_tree_add_item(guid_tree, hf_app_id, tvb, offset+4, 4, ENC_BIG_ENDIAN);
    appid_tree = proto_item_add_subtree(ti, ett_rtps_app_id);

    /* InstanceId */
    proto_tree_add_item(appid_tree, hf_app_id_instance_id, tvb, offset+4, 3, ENC_BIG_ENDIAN);
    /* AppKind */
    proto_tree_add_item(appid_tree, hf_app_id_app_kind, tvb, offset+7, 1, ENC_BIG_ENDIAN);
  }
}

/* ------------------------------------------------------------------------- */
/* Insert in the protocol tree the next 12 bytes interpreted as GuidPrefix
 * If tree is specified, it fills up the protocol tree item:
 *  - hf_rtps_guid_prefix
 *  - hf_rtps_host_id
 *  - hf_rtps_app_id
 *  - hf_rtps_counter
 */
static void rtps_util_add_guid_prefix_v2(proto_tree *tree, tvbuff_t *tvb, gint offset,
                                      int hf_prefix, int hf_host_id, int hf_app_id,
                                      int hf_counter, const guint8 * label) {
  const guint8 * safe_label;

  safe_label = (label == NULL) ? (const guint8 *)"guidPrefix" : label;

  if (tree) {
    proto_item * ti, *hidden_item;
    proto_tree * guid_tree;

    /* The text node (root of the guid prefix sub-tree) */
    ti = proto_tree_add_text(tree, tvb, offset, 12, "%s", safe_label);
    guid_tree = proto_item_add_subtree(ti, ett_rtps_guid_prefix);

    /* The numeric value (used for searches) */
    hidden_item = proto_tree_add_item(guid_tree, hf_prefix, tvb, offset, 8, ENC_NA);
    PROTO_ITEM_SET_HIDDEN(hidden_item);

    /* Host Id */
    proto_tree_add_item(guid_tree, hf_host_id, tvb, offset, 4, ENC_BIG_ENDIAN);

    /* App Id */
    proto_tree_add_item(guid_tree, hf_app_id, tvb, offset+4, 4, ENC_BIG_ENDIAN);

    /* Counter */
    proto_tree_add_item(guid_tree, hf_counter, tvb, offset+8, 4, ENC_BIG_ENDIAN);
  }
}

/* ------------------------------------------------------------------------- */
 /* Insert the entityId from the next 4 bytes. Since there are more than
  * one entityId, we need to specify also the IDs of the entityId (and its
  * sub-components), as well as the label identifying it.
  * Returns true if the entityKind is one of the NDDS built-in entities.
  */
int rtps_util_add_entity_id(proto_tree *tree, tvbuff_t * tvb, gint offset,
                            int hf_item, int hf_item_entity_key, int hf_item_entity_kind,
                            int subtree_entity_id, const char *label, guint32* entity_id_out) {
  guint32 entity_id   = tvb_get_ntohl(tvb, offset);
  guint32 entity_key  = (entity_id >> 8);
  guint8  entity_kind = (entity_id & 0xff);
  const char *str_predef = try_val_to_str(entity_id, entity_id_vals);

  if (entity_id_out != NULL) {
    *entity_id_out = entity_id;
  }

  if (tree != NULL) {
    proto_tree * entity_tree;
    proto_item * ti;

    if (str_predef == NULL) {
      /* entityId is not a predefined value, format it */
      ti = proto_tree_add_uint_format(tree, hf_item, tvb, offset, 4, entity_id,
                        "%s: 0x%08x (%s: 0x%06x)",
                        label, entity_id,
                        val_to_str(entity_kind, entity_kind_vals, "unknown kind (%02x)"),
                        entity_key);
    } else {
      /* entityId is a predefined value */
      ti = proto_tree_add_uint_format(tree, hf_item, tvb, offset, 4, entity_id,
                        "%s: %s (0x%08x)", label, str_predef, entity_id);
    }

    entity_tree = proto_item_add_subtree(ti, subtree_entity_id);

    proto_tree_add_item(entity_tree, hf_item_entity_key, tvb, offset, 3, ENC_BIG_ENDIAN);
    proto_tree_add_item(entity_tree, hf_item_entity_kind, tvb, offset+3, 1, ENC_BIG_ENDIAN);
  }

  /* is a built-in entity if the bit M and R (5 and 6) of the entityKind are set */
  /*  return ((entity_kind & 0xc0) == 0xc0); */
  return ( entity_id == ENTITYID_BUILTIN_TOPIC_WRITER ||
           entity_id == ENTITYID_BUILTIN_TOPIC_READER ||
           entity_id == ENTITYID_BUILTIN_PUBLICATIONS_WRITER ||
           entity_id == ENTITYID_BUILTIN_PUBLICATIONS_READER ||
           entity_id == ENTITYID_BUILTIN_SUBSCRIPTIONS_WRITER ||
           entity_id == ENTITYID_BUILTIN_SUBSCRIPTIONS_READER ||
           entity_id == ENTITYID_BUILTIN_SDP_PARTICIPANT_WRITER ||
           entity_id == ENTITYID_BUILTIN_SDP_PARTICIPANT_READER );
}

/* ------------------------------------------------------------------------- */
 /* Insert the entityId from the next 4 bytes as a generic one (not connected
  * to any protocol field). It simply insert the content as a simple text entry
  * and returns in the passed buffer only the value (without the label).
  */
void rtps_util_add_generic_entity_id(proto_tree *tree, tvbuff_t * tvb, gint offset, const char* label,
                                     int hf_item, int hf_item_entity_key, int hf_item_entity_kind,
                                     int subtree_entity_id) {
  guint32 entity_id   = tvb_get_ntohl(tvb, offset);
  guint32 entity_key  = (entity_id >> 8);
  guint8  entity_kind = (entity_id & 0xff);
  const char *str_predef = try_val_to_str(entity_id, entity_id_vals);
  proto_item *ti;
  proto_tree *entity_tree;

  if (str_predef == NULL) {
    /* entityId is not a predefined value, format it */
    ti = proto_tree_add_uint_format(tree, hf_item, tvb, offset, 4, entity_id,
                        "%s: 0x%08x (%s: 0x%06x)", label, entity_id,
                        val_to_str(entity_kind, entity_kind_vals, "unknown kind (%02x)"),
                        entity_key);
  } else {
    /* entityId is a predefined value */
    ti = proto_tree_add_uint_format_value(tree, hf_item, tvb, offset, 4, entity_id,
                        "%s: %s (0x%08x)", label, str_predef, entity_id);
  }

  entity_tree = proto_item_add_subtree(ti, subtree_entity_id);

  proto_tree_add_item(entity_tree, hf_item_entity_key, tvb, offset, 3, ENC_BIG_ENDIAN);
  proto_tree_add_item(entity_tree, hf_item_entity_kind, tvb, offset+3, 1, ENC_BIG_ENDIAN);

}

/* ------------------------------------------------------------------------- */
 /* Interpret the next 12 octets as a generic GUID and insert it in the protocol
  * tree as simple text (no reference fields are set).
  * It is mostly used in situation where is not required to perform search for
  * this kind of GUID (i.e. like in some DATA parameter lists).
  */
static void rtps_util_add_generic_guid_v1(proto_tree *tree, tvbuff_t * tvb, gint offset,
                        int hf_guid, int hf_host_id, int hf_app_id, int hf_app_id_instance_id,
                        int hf_app_id_app_kind, int hf_entity, int hf_entity_key,
                        int hf_entity_kind) {

  guint64 prefix;
  guint32 host_id, app_id, entity_id;
  proto_item* ti;
  proto_tree *guid_tree, *appid_tree, *entity_tree;

  /* Read typed data */
  prefix = tvb_get_ntoh64(tvb, offset);
  host_id   = tvb_get_ntohl(tvb, offset);
  app_id    = tvb_get_ntohl(tvb, offset + 4);
  entity_id = tvb_get_ntohl(tvb, offset + 8);

  ti = proto_tree_add_uint64_format_value(tree, hf_guid, tvb, offset, 8, prefix, "%08x %08x %08x",
                                          host_id, app_id, entity_id);

  guid_tree = proto_item_add_subtree(ti, ett_rtps_generic_guid);

  /* Host Id */
  proto_tree_add_item(guid_tree, hf_host_id, tvb, offset, 4, ENC_BIG_ENDIAN);

  /* AppId (root of the app_id sub-tree) */
  ti = proto_tree_add_item(guid_tree, hf_app_id, tvb, offset+4, 4, ENC_BIG_ENDIAN);
  appid_tree = proto_item_add_subtree(ti, ett_rtps_app_id);

  /* InstanceId */
  proto_tree_add_item(appid_tree, hf_app_id_instance_id, tvb, offset+4, 3, ENC_BIG_ENDIAN);
  /* AppKind */
  proto_tree_add_item(appid_tree, hf_app_id_app_kind, tvb, offset+7, 1, ENC_BIG_ENDIAN);

  /* Entity (root of the app_id sub-tree) */
  ti = proto_tree_add_item(guid_tree, hf_entity, tvb, offset+8, 4, ENC_BIG_ENDIAN);
  entity_tree = proto_item_add_subtree(ti, ett_rtps_entity);

  proto_tree_add_item(entity_tree, hf_entity_key, tvb, offset+8, 3, ENC_BIG_ENDIAN);
  proto_tree_add_item(entity_tree, hf_entity_kind, tvb, offset+11, 1, ENC_BIG_ENDIAN);
}

/* ------------------------------------------------------------------------- */
 /* Interpret the next 16 octets as a generic GUID and insert it in the protocol
  * tree as simple text (no reference fields are set).
  * It is mostly used in situation where is not required to perform search for
  * this kind of GUID (i.e. like in some DATA parameter lists).
  */
static void rtps_util_add_generic_guid_v2(proto_tree *tree, tvbuff_t * tvb, gint offset,
                        int hf_guid, int hf_host_id, int hf_app_id, int hf_app_id_instance_id,
                        int hf_app_id_app_kind, int hf_counter,
                        int hf_entity, int hf_entity_key, int hf_entity_kind) {

  guint64 prefix;
  guint32 host_id, app_id, entity_id, counter;
  proto_item *ti;
  proto_tree *guid_tree, *appid_tree, *entity_tree;

  /* Read typed data */
  prefix = tvb_get_ntoh64(tvb, offset);
  host_id   = tvb_get_ntohl(tvb, offset);
  app_id    = tvb_get_ntohl(tvb, offset + 4);
  counter   = tvb_get_ntohl(tvb, offset + 8);
  entity_id = tvb_get_ntohl(tvb, offset + 12);

  ti = proto_tree_add_uint64_format_value(tree, hf_guid, tvb, offset, 8, prefix, "%08x %08x %08x %08x",
                                          host_id, app_id, counter, entity_id);

  guid_tree = proto_item_add_subtree(ti, ett_rtps_generic_guid);

  /* Host Id */
  proto_tree_add_item(guid_tree, hf_host_id, tvb, offset, 4, ENC_BIG_ENDIAN);

  /* AppId (root of the app_id sub-tree) */
  ti = proto_tree_add_item(guid_tree, hf_app_id, tvb, offset+4, 4, ENC_BIG_ENDIAN);
  appid_tree = proto_item_add_subtree(ti, ett_rtps_app_id);

  /* InstanceId */
  proto_tree_add_item(appid_tree, hf_app_id_instance_id, tvb, offset+4, 3, ENC_BIG_ENDIAN);
  /* AppKind */
  proto_tree_add_item(appid_tree, hf_app_id_app_kind, tvb, offset+7, 1, ENC_BIG_ENDIAN);

  /* Counter */
  proto_tree_add_item(guid_tree, hf_counter, tvb, offset+8, 4, ENC_BIG_ENDIAN);

  /* Entity (root of the app_id sub-tree) */
  ti = proto_tree_add_item(guid_tree, hf_entity, tvb, offset+12, 4, ENC_BIG_ENDIAN);
  entity_tree = proto_item_add_subtree(ti, ett_rtps_entity);

  proto_tree_add_item(entity_tree, hf_entity_key, tvb, offset+12, 3, ENC_BIG_ENDIAN);
  proto_tree_add_item(entity_tree, hf_entity_kind, tvb, offset+15, 1, ENC_BIG_ENDIAN);
}


/* ------------------------------------------------------------------------- */
/* Insert in the protocol tree the next 8 bytes interpreted as sequence
 * number.
 */
guint64 rtps_util_add_seq_number(proto_tree *tree,
                        tvbuff_t * tvb,
                        gint       offset,
                        gboolean   little_endian,
                        const char *label) {
  guint64 hi = (guint64)NEXT_guint32(tvb, offset, little_endian);
  guint64 lo = (guint64)NEXT_guint32(tvb, offset+4, little_endian);
  guint64 all = (hi << 32) | lo;

  proto_tree_add_int64_format(tree, hf_rtps_sm_seq_number, tvb, offset, 8,
                        all, "%s: %" G_GINT64_MODIFIER "u", label, all);

  return all;
}


/* ------------------------------------------------------------------------- */
/* Insert in the protocol tree the next 8 bytes interpreted as NtpTime
 */
void rtps_util_add_ntp_time(proto_tree *tree,
                        tvbuff_t * tvb,
                        gint       offset,
                        gboolean   little_endian,
                        int hf_time) {

  proto_tree_add_item(tree, hf_time, tvb, offset, 8,
                      ENC_TIME_NTP|(little_endian ? ENC_LITTLE_ENDIAN : ENC_BIG_ENDIAN));

}

/* ------------------------------------------------------------------------- */
/* Insert in the protocol tree the next data interpreted as a String
 * Returns the new offset (after reading the string)
 */
gint rtps_util_add_string(proto_tree *tree, tvbuff_t* tvb, gint offset,
                          int hf_item, gboolean little_endian) {
  guint8 * retVal = NULL;
  guint32 size = NEXT_guint32(tvb, offset, little_endian);

  if (size > 0) {
    retVal = tvb_get_string_enc(wmem_packet_scope(), tvb, offset+4, size, ENC_ASCII);
  }

  proto_tree_add_string(tree, hf_item, tvb, offset, size+4,
                        (size == 0) ? (const guint8 *)"" : retVal);

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
/* Insert in the protocol tree the next data interpreted as a port (unsigned
 * 32-bit integer)
 */
void rtps_util_add_port(proto_tree *tree, packet_info *pinfo, tvbuff_t * tvb,
                        gint offset, gboolean little_endian, int hf_item) {
  proto_item* ti;
  guint32 port = NEXT_guint32(tvb, offset+4, little_endian);

  ti = proto_tree_add_uint(tree, hf_item, tvb, offset, 4, port);
  if (port == PORT_INVALID)
    expert_add_info(pinfo, ti, &ei_rtps_port_invalid);
}


/* ------------------------------------------------------------------------- */
/* Insert in the protocol tree the next bytes interpreted as
 * DurabilityServiceQosPolicy
 */
void rtps_util_add_durability_service_qos(proto_tree *tree,
                        tvbuff_t * tvb,
                        gint       offset,
                        gboolean   little_endian) {
  proto_item *ti;
  proto_tree *subtree;

  ti = proto_tree_add_text(tree, tvb, offset, 28, "PID_DURABILITY_SERVICE");
  subtree = proto_item_add_subtree(ti, ett_rtps_durability_service);

  rtps_util_add_ntp_time(subtree, tvb, offset, little_endian, hf_rtps_durability_service_cleanup_delay);
  proto_tree_add_item(subtree, hf_rtps_durability_service_history_kind, tvb, offset+8, 4,
                            little_endian ? ENC_LITTLE_ENDIAN : ENC_BIG_ENDIAN);
  proto_tree_add_item(subtree, hf_rtps_durability_service_history_depth, tvb, offset+12, 4,
                            little_endian ? ENC_LITTLE_ENDIAN : ENC_BIG_ENDIAN);
  proto_tree_add_item(subtree, hf_rtps_durability_service_max_samples, tvb, offset+16, 4,
                            little_endian ? ENC_LITTLE_ENDIAN : ENC_BIG_ENDIAN);
  proto_tree_add_item(subtree, hf_rtps_durability_service_max_instances, tvb, offset+20, 4,
                            little_endian ? ENC_LITTLE_ENDIAN : ENC_BIG_ENDIAN);
  proto_tree_add_item(subtree, hf_rtps_durability_service_max_samples_per_instances, tvb, offset+24, 4,
                            little_endian ? ENC_LITTLE_ENDIAN : ENC_BIG_ENDIAN);
}

/* ------------------------------------------------------------------------- */
/* Insert in the protocol tree the next bytes interpreted as Liveliness
 * QoS Policy structure.
 */
void rtps_util_add_liveliness_qos(proto_tree *tree, tvbuff_t * tvb, gint offset, gboolean little_endian) {

  proto_item *ti;
  proto_tree *subtree;

  ti = proto_tree_add_text(tree, tvb, offset, 12, "PID_LIVELINESS");
  subtree = proto_item_add_subtree(ti, ett_rtps_liveliness);

  proto_tree_add_item(subtree, hf_rtps_liveliness_kind, tvb, offset, 4,
                            little_endian ? ENC_LITTLE_ENDIAN : ENC_BIG_ENDIAN);
  rtps_util_add_ntp_time(subtree, tvb, offset+4, little_endian, hf_rtps_liveliness_lease_duration);
}

/* ------------------------------------------------------------------------- */
/* Insert in the protocol tree the next bytes interpreted as Sequence of
 * Strings.
 * The formatted buffer is: "string1", "string2", "string3", ...
 * Returns the new updated offset
 */
gint rtps_util_add_seq_string(proto_tree *tree, tvbuff_t* tvb, gint offset,
                              gboolean little_endian, int param_length, int hf_numstring,
                              int hf_string, const char *label) {
  guint32 i, num_strings, size;
  const guint8 * retVal;
  proto_tree *string_tree;
  proto_item *ti;

  num_strings = NEXT_guint32(tvb, offset, little_endian);
  proto_tree_add_int(tree, hf_numstring, tvb, offset, 4, num_strings);
  offset += 4;

  /* Create the string node with a fake string, the replace it later */
  ti = proto_tree_add_text(tree, tvb, offset, param_length-8, "%s", label);
  string_tree = proto_item_add_subtree(ti, ett_rtps_seq_string);

  for (i = 0; i < num_strings; ++i) {
    size = NEXT_guint32(tvb, offset, little_endian);

    if (size > 0) {
      retVal = tvb_get_string_enc(wmem_packet_scope(), tvb, offset+4, size, ENC_ASCII);
    } else {
      retVal = (const guint8 *)"";
    }

    proto_tree_add_string_format(string_tree, hf_string, tvb, offset, size+4, retVal,
        "%s[%d]: %s", label, i, retVal);

    offset += (4 + ((size + 3) & 0xfffffffc));
  }

  return offset;
}

/* ------------------------------------------------------------------------- */
/* Insert in the protocol tree the next bytes interpreted as Sequence of
 * longs.
 * The formatted buffer is: val1, val2, val3, ...
 * Returns the new updated offset
 */
gint rtps_util_add_seq_ulong(proto_tree *tree, tvbuff_t * tvb, gint offset, int hf_item,
                        gboolean little_endian, int param_length _U_, const char *label) {
  guint32 num_elem;
  guint32 i;
  proto_tree *string_tree;
  proto_item *ti;

  num_elem = NEXT_guint32(tvb, offset, little_endian);
  offset += 4;

  /* Create the string node with an empty string, the replace it later */
  ti = proto_tree_add_text(tree, tvb, offset, num_elem*4, "%s (%d elements)", label, num_elem);
  string_tree = proto_item_add_subtree(ti, ett_rtps_seq_ulong);

  for (i = 0; i < num_elem; ++i) {
    proto_tree_add_item(string_tree, hf_item, tvb, offset, 4, little_endian ? ENC_LITTLE_ENDIAN : ENC_BIG_ENDIAN);
    offset += 4;
  }

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
static gint rtps_util_add_typecode(proto_tree *tree, tvbuff_t * tvb, gint offset, gboolean little_endian,
                        int indent_level, int is_pointer, guint16 bitfield, int is_key, const gint offset_begin,
                        char* name,
                        int seq_max_len, /* -1 = not a sequence field */
                        guint32*  arr_dimension, /* if !NULL: array of 10 int */
                        int ndds_40_hack) {
  const gint original_offset = offset;
  guint32 tk_id;
  guint16 tk_size;
  unsigned int i;
  char*   indent_string;
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
  indent_string = (char *)wmem_alloc(wmem_epan_scope(), (indent_level*2)+1);
  memset(indent_string, ' ', indent_level*2);
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
        guint32 disc_offset_begin, num_members, member_name_len;
        guint16 member_length;
        guint8 *member_name = NULL;
        guint8  member_is_pointer;
        guint32 next_offset, field_offset_begin, member_label_count, discriminator_enum_name_length;
        gint32  member_label;
        guint   j;

        /* - - - - - - -      Union name      - - - - - - - */
        /* Pad-align */
        LONG_ALIGN(offset);

        /* Get structure name length */
        struct_name_len = NEXT_guint32(tvb, offset, little_endian);
        offset += 4;
        struct_name = tvb_get_string_enc(wmem_packet_scope(), tvb, offset, struct_name_len, ENC_ASCII);
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
          discriminator_enum_name = tvb_get_string_enc(wmem_packet_scope(), tvb, offset+4, discriminator_enum_name_length, ENC_ASCII);
        }
        offset = disc_offset_begin + disc_size;
#if 0
        field_offset_begin = offset;
        offset += rtps_util_add_typecode(
                          tree,
                          tvb,
                          offset,
                          little_endian,
                          indent_level+1,
                          0,
                          0,
                          0,
                          field_offset_begin,
                          member_name,
                          -1,
                          NULL,
                          ndds_40_hack);
#endif

        /* Add the entry of the union in the tree */
        proto_tree_add_text(tree, tvb, original_offset, retVal,
                    "%sunion %s (%s%s%s) {",
                    indent_string, struct_name, discriminator_name,
                    (discriminator_enum_name ? " " : ""),
                    (discriminator_enum_name ? discriminator_enum_name : ""));

        if (seq_max_len != -1) {
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
          member_name = tvb_get_string_enc(wmem_packet_scope(), tvb, offset, member_name_len, ENC_ASCII);
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
            proto_tree_add_text(tree, tvb, field_offset_begin, retVal,
                    "%s  case %d:", indent_string, member_label);
          }

          offset += rtps_util_add_typecode(tree, tvb, offset, little_endian,
                    indent_level+2, member_is_pointer, 0, 0, field_offset_begin,
                    member_name, -1, NULL, ndds_40_hack);
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
        gint8 * struct_name;
        guint16 member_length, member_bitfield;
        guint8  member_is_pointer, member_is_key;
        guint32 struct_name_len, num_members, member_name_len,
                next_offset, field_offset_begin, ordinal_number;
        guint8 *member_name = NULL;
        const char * typecode_name;

        /* Pad-align */
        LONG_ALIGN(offset);

        /* Get structure name length */
        struct_name_len = NEXT_guint32(tvb, offset, little_endian);
        offset += 4;

        /* struct name */
        struct_name = tvb_get_string_enc(wmem_packet_scope(), tvb, offset, struct_name_len, ENC_ASCII);
        offset += struct_name_len;


        if (tk_id == RTI_CDR_TK_ENUM) {
          typecode_name = "enum";
        } else {
          typecode_name = "struct";
        }

        if (seq_max_len != -1) {
          /* We're dissecting a sequence of struct, bypass the seq definition */
          g_snprintf(type_name, 40, "%s", struct_name);
          break;
        }
        /* Prints it */
        proto_tree_add_text(tree, tvb, original_offset, retVal, "%s%s %s {",
                    indent_string, typecode_name, struct_name);

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
          member_name = tvb_get_string_enc(wmem_packet_scope(), tvb, offset, member_name_len, ENC_ASCII);
          offset += member_name_len;

          if (tk_id == RTI_CDR_TK_ENUM) {
            /* ordinal number */
            LONG_ALIGN(offset);
            ordinal_number = NEXT_guint32(tvb, offset, little_endian);
            offset += 4;

            proto_tree_add_text(tree, tvb, field_offset_begin, (offset-field_offset_begin),
                  "%s  %s = %d;", indent_string, member_name, ordinal_number);
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

            offset += rtps_util_add_typecode(tree, tvb, offset, little_endian,
                          indent_level+1, member_is_pointer, member_bitfield, member_is_key,
                          field_offset_begin, member_name, -1, NULL, ndds_40_hack);
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
        /*offset += */rtps_util_add_typecode(tree, tvb, offset, little_endian, indent_level,
                          is_pointer, bitfield, is_key, offset_begin, name,
                          seq_max_len2, NULL, ndds_40_hack);
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

        if (dim_max > MAX_ARRAY_DIMENSION) {
            /* We don't have a tree item to add expert info to... */
            dim_max = MAX_ARRAY_DIMENSION;
        }

        for (i = 0; i < MAX_ARRAY_DIMENSION; ++i) size[i] = 0;
        for (i = 0; i < dim_max; ++i) {
          size[i] = NEXT_guint32(tvb, offset, little_endian);
          offset += 4;
        }

        /* Recursive decode seq typecode */
        /*offset += */rtps_util_add_typecode(tree, tvb, offset, little_endian,
                          indent_level, is_pointer, bitfield, is_key, offset_begin,
                          name, -1, size, ndds_40_hack);
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
        alias_name = tvb_get_string_enc(wmem_packet_scope(), tvb, offset, alias_name_length, ENC_ASCII);
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
    case RTI_CDR_TK_VALUE: {
        /* Not fully dissected for now */
        /* Pad-align */
        guint32 value_name_len;
        gint8 * value_name;
        LONG_ALIGN(offset);

        /* Get structure name length */
        value_name_len = NEXT_guint32(tvb, offset, little_endian);
        offset += 4;

        /* value name */
        value_name = tvb_get_string_enc(wmem_packet_scope(), tvb, offset, value_name_len, ENC_ASCII);
        offset += value_name_len;

        g_snprintf(type_name, 40, "valuetype %s", value_name);
        break;
    }
  } /* switch(tk_id) */

  /* Sequence print */
  if (seq_max_len != -1) {
    proto_tree_add_text(tree, tvb, offset_begin, (offset-offset_begin),
                  "%ssequence<%s, %d> %s%s;%s",
                  indent_string, type_name, seq_max_len,
                  is_pointer ? "*" : "",
                  name ? name : "",
                  is_key ? KEY_COMMENT : "");
    return retVal;
  }

  /* Array print */
  if (arr_dimension != NULL) {
    /* Printing an array */
    wmem_strbuf_t *dim_str = wmem_strbuf_new_label(wmem_packet_scope());
    for (i = 0; i < MAX_ARRAY_DIMENSION; ++i) {
      if (arr_dimension[i] != 0) {
        wmem_strbuf_append_printf(dim_str, "[%d]", arr_dimension[i]);
      } else {
        break;
      }
    }
    proto_tree_add_text(tree, tvb, offset_begin, (offset-offset_begin),
                  "%s%s %s%s;%s",
                  indent_string, type_name, name ? name : "",
                  wmem_strbuf_get_str(dim_str), is_key ? KEY_COMMENT : "");
    return retVal;
  }

  /* Bitfield print */
  if (bitfield != 0xffff && name != NULL && is_pointer == 0) {
    proto_tree_add_text(tree, tvb, offset_begin, (offset-offset_begin),
                  "%s%s %s:%d;%s",
                  indent_string, type_name, name ? name : "",
                  bitfield, is_key ? KEY_COMMENT : "");
    return retVal;
  }

  /* Everything else */
  proto_tree_add_text(tree, tvb, offset_begin, (offset-offset_begin),
                  "%s%s%s%s%s;%s", indent_string, type_name,
                  name ? " " : "",
                  is_pointer ? "*" : "",
                  name ? name : "",
                  is_key ? KEY_COMMENT : "");
  return retVal;
}

/* ------------------------------------------------------------------------- */
/* Insert in the protocol tree the next bytes interpreted as Sequence of
 * Octects.
 * The formatted buffer is: [ 0x01, 0x02, 0x03, 0x04, ...]
 * The maximum number of elements displayed is 10, after that a '...' is
 * inserted.
 */
void rtps_util_add_seq_octets(proto_tree *tree, packet_info *pinfo, tvbuff_t* tvb,
                              gint offset, gboolean little_endian, int param_length, int hf_id) {
  guint32 seq_length;
  proto_item *ti;

  seq_length = NEXT_guint32(tvb, offset, little_endian);

  ti = proto_tree_add_text(tree, tvb, offset, 4, "sequenceSize: %d octects", seq_length);

  offset += 4;
  if (param_length < 4 + (int)seq_length) {
    expert_add_info_format(pinfo, ti, &ei_rtps_parameter_value_invalid, "ERROR: Parameter value too small");
    return;
  }

  proto_tree_add_item(tree, hf_id, tvb, offset+4, seq_length,
                      little_endian ? ENC_LITTLE_ENDIAN : ENC_BIG_ENDIAN);
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
                        gboolean   little_endian,
                        const char *label _U_) {
  gint32 num_bits;
  guint32 data;
  wmem_strbuf_t *temp_buff = wmem_strbuf_new_label(wmem_packet_scope());
  int i, j, idx;
  gchar *last_one;
  proto_item * ti;
  proto_tree * bitmap_tree;
  const gint original_offset = offset;
  guint32 datamask;

  ti = proto_tree_add_text(tree, tvb, original_offset, offset-original_offset, "%s", label);
  bitmap_tree = proto_item_add_subtree(ti, ett_rtps_bitmap);

  /* Bitmap base sequence number */
  rtps_util_add_seq_number(bitmap_tree, tvb, offset, little_endian, "bitmapBase");
  offset += 8;

  /* Reads the bitmap size */
  num_bits = NEXT_guint32(tvb, offset, little_endian);
  proto_tree_add_uint(bitmap_tree, hf_rtps_bitmap_num_bits, tvb, offset, 4, num_bits);
  offset += 4;

  /* Reads the bits (and format the print buffer) */
  idx = 0;
  for (i = 0; i < num_bits; i += 32) {
    data = NEXT_guint32(tvb, offset, little_endian);
    offset += 4;
    for (j = 0; j < 32; ++j) {
      datamask = (1 << (31-j));
      wmem_strbuf_append_c(temp_buff, ((data & datamask) == datamask) ? '1':'0');
      ++idx;
      if ((idx >= num_bits) || (wmem_strbuf_get_len(temp_buff) >= (ITEM_LABEL_LENGTH - 1))) {
        break;
      }
    }
  }

  /* removes all the ending '0' */
  last_one = strrchr(wmem_strbuf_get_str(temp_buff), '1');
  if (last_one) {
    wmem_strbuf_truncate(temp_buff, (gsize) (last_one - wmem_strbuf_get_str(temp_buff)));
  }

  if (wmem_strbuf_get_len(temp_buff) > 0) {
    proto_tree_add_text(bitmap_tree,
                        tvb,
                        original_offset + 12,
                        offset - original_offset - 12,
                        "bitmap: %s",
                        wmem_strbuf_get_str(temp_buff));
  }

  proto_item_set_len(ti, offset-original_offset);
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
static int rtps_util_add_fragment_number_set(proto_tree *tree, packet_info *pinfo, tvbuff_t * tvb,
                        gint offset, gboolean little_endian, const char *label, gint section_size) {
  guint64 base;
  gint32 num_bits;
  guint32 data;
  wmem_strbuf_t *temp_buff = wmem_strbuf_new_label(wmem_packet_scope());
  gchar *last_one;
  int i, j, idx;
  proto_item * ti;
  proto_tree * bitmap_tree;
  const gint original_offset = offset;
  guint32 datamask;
  gint expected_size;
  gint base_size;

  ti = proto_tree_add_text(tree, tvb, original_offset, offset-original_offset, "%s", label);

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
      expert_add_info_format(pinfo, ti, &ei_rtps_parameter_value_invalid, "Illegal size for fragment number set");
      return -1;
    }
  }

  /* Reads the bits (and format the print buffer) */
  idx = 0;
  for (i = 0; i < num_bits; i += 32) {
    data = NEXT_guint32(tvb, offset, little_endian);
    offset += 4;
    for (j = 0; j < 32; ++j) {
      datamask = (1 << (31-j));
      wmem_strbuf_append_c(temp_buff, ((data & datamask) == datamask) ? '1':'0');
      ++idx;
      if ((idx >= num_bits) || (wmem_strbuf_get_len(temp_buff) >= (ITEM_LABEL_LENGTH - 1))) {
        break;
      }
    }
  }

  /* removes all the ending '0' */
  last_one = strrchr(wmem_strbuf_get_str(temp_buff), '1');
  if (last_one) {
    wmem_strbuf_truncate(temp_buff, (gsize) (last_one - wmem_strbuf_get_str(temp_buff)));
  }

  bitmap_tree = proto_item_add_subtree(ti, ett_rtps_bitmap);

  if (base_size == 8) {
    proto_tree_add_uint64(bitmap_tree, hf_rtps_fragment_number_base64, tvb, original_offset, 8,
                    base);
  } else {
    proto_tree_add_item(bitmap_tree, hf_rtps_fragment_number_base, tvb, original_offset, base_size,
                    little_endian ? ENC_LITTLE_ENDIAN : ENC_BIG_ENDIAN);
  }
  proto_tree_add_uint(bitmap_tree, hf_rtps_fragment_number_num_bits, tvb, original_offset + base_size, 4, num_bits);

  if (wmem_strbuf_get_len(temp_buff) > 0) {
    proto_tree_add_text(bitmap_tree, tvb,
                        original_offset + base_size + 4,
                        offset - original_offset - base_size - 4,
                        "bitmap: %s", wmem_strbuf_get_str(temp_buff));
  }

  proto_item_set_len(ti, offset-original_offset);
  return offset;
}

/* ------------------------------------------------------------------------- */
/* Decode the submessage flags
 */
static void rtps_util_decode_flags(proto_tree * tree, tvbuff_t *tvb, gint offset,
                        guint8 flags, const struct Flag_definition * flag_def) {

  proto_item * ti;
  proto_tree * flags_tree;
  int i, j;
  char flags_str[20];

  ti = proto_tree_add_uint(tree, hf_rtps_sm_flags, tvb, offset, 1, flags);
  proto_item_append_text(ti, " ( ");
  for (i = 0; i < 8; ++i) {
    proto_item_append_text(ti, "%c ", ((flags & (1<<(7-i))) ? flag_def[i].letter : RESERVEDFLAG_CHAR));
  }
  proto_item_append_text(ti, ")");

  flags_tree = proto_item_add_subtree(ti, ett_rtps_flags);

  for (i = 0; i < 8; ++i) {
    int is_set = (flags & (1 << (7-i)));

    for (j = 0; j < 8; ++j) {
      flags_str[j] = (i == j) ? (is_set ? '1' : '0') : '.';
    }
    flags_str[8] = '\0';

    proto_tree_add_text(flags_tree, tvb, offset, 1, "%s = %s: %s",
                        flags_str, flag_def[i].description,
                        is_set ? "Set" : "Not set");
  }

}

static void rtps_util_decode_flags_16bit(proto_tree * tree, tvbuff_t *tvb, gint offset,
                        guint16 flags, const struct Flag_definition * flag_def) {

  proto_item * ti;
  proto_tree * flags_tree;
  int i, j;
  char flags_str[20];

  ti = proto_tree_add_uint(tree, hf_rtps_sm_flags, tvb, offset, 2, flags);
  proto_item_append_text(ti, " ( ");
  for (i = 0; i < 16; ++i) {
    proto_item_append_text(ti, "%c ", ((flags & (1<<(15-i))) ? flag_def[i].letter : RESERVEDFLAG_CHAR));
  }
  proto_item_append_text(ti, ")");

  flags_tree = proto_item_add_subtree(ti, ett_rtps_flags);

  for (i = 0; i < 16; ++i) {
    int is_set = (flags & (1 << (15-i)));

    for (j = 0; j < 16; ++j) {
      flags_str[j] = (i == j) ? (is_set ? '1' : '0') : '.';
    }
    flags_str[16] = '\0';

    proto_tree_add_text(flags_tree, tvb, offset, 2, "%s = %s: %s",
                        flags_str,
                        flag_def[i].description,
                        is_set ? "Set" : "Not set");
  }
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
 */
#define ENSURE_LENGTH(size)                                                          \
        if (param_length < size) {                                                   \
          expert_add_info_format(pinfo, param_len_item, &ei_rtps_parameter_value_invalid, "ERROR: parameter value too small (must be at least %d octects)", size); \
          break;                                                                     \
        }

static gboolean dissect_parameter_sequence_v1(proto_tree *rtps_parameter_tree, packet_info *pinfo, tvbuff_t *tvb,
                        proto_item* parameter_item, proto_item*  param_len_item, gint offset,
                        gboolean little_endian, int size, int param_length,
                        guint16 parameter, guint16 version) {
  proto_item *ti;
  proto_tree *subtree;

  switch(parameter) {

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
      rtps_util_add_ntp_time(rtps_parameter_tree, tvb, offset, little_endian,
                             hf_rtps_participant_lease_duration);
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
      rtps_util_add_ntp_time(rtps_parameter_tree, tvb, offset, little_endian,
                             hf_rtps_time_based_filter_minimum_separation);
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
      rtps_util_add_string(rtps_parameter_tree, tvb, offset, hf_rtps_param_topic_name, little_endian);
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
      proto_tree_add_item(rtps_parameter_tree, hf_rtps_param_strength, tvb, offset, 4,
                          little_endian ? ENC_LITTLE_ENDIAN : ENC_BIG_ENDIAN);
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
     *  +---------------+---------------+---------------+---------------+
     */
    case PID_TYPE_NAME:
      rtps_util_add_string(rtps_parameter_tree, tvb, offset, hf_rtps_param_type_name, little_endian);
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
      rtps_util_add_port(rtps_parameter_tree, pinfo, tvb, offset, little_endian, hf_rtps_param_port);
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
      proto_tree_add_item(rtps_parameter_tree, hf_rtps_expects_inline_qos, tvb, offset, 1, ENC_NA );
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
      rtps_util_add_ipv4_address_t(rtps_parameter_tree, pinfo, tvb, offset,
                                    little_endian, hf_param_ip_address);
      break;

    /* 0...2...........7...............15.............23...............31
     * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     * | PID_PROTOCOL_VERSION          |            0x0004             |
     * +---------------+---------------+---------------+---------------+
     * | uint8 major   | uint8 minor   |    N O T    U S E D           |
     * +---------------+---------------+---------------+---------------+
     */
    case PID_PROTOCOL_VERSION:
      ENSURE_LENGTH(2);
      rtps_util_add_protocol_version(rtps_parameter_tree, tvb, offset);
      break;

    /* 0...2...........7...............15.............23...............31
     * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     * | PID_VENDOR_ID                 |            0x0004             |
     * +---------------+---------------+---------------+---------------+
     * | uint8 major   | uint8 minor   |    N O T    U S E D           |
     * +---------------+---------------+---------------+---------------+
     */
    case PID_VENDOR_ID:
      ENSURE_LENGTH(2);
      rtps_util_add_vendor_id(NULL, tvb, offset);
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
      proto_tree_add_item(rtps_parameter_tree, hf_rtps_reliability_kind, tvb, offset, 4,
                        little_endian ? ENC_LITTLE_ENDIAN : ENC_BIG_ENDIAN);

      /* Older version of the protocol (and for PID_RELIABILITY_OFFERED)
       * this parameter was carrying also a NtpTime called
       * 'maxBlockingTime'.
       */
      if (size == 12) {
        rtps_util_add_ntp_time(rtps_parameter_tree, tvb, offset + 4,
                    little_endian, hf_rtps_reliability_max_blocking_time);
      }
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
      rtps_util_add_liveliness_qos(rtps_parameter_tree, tvb, offset, little_endian);
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
      proto_tree_add_item(rtps_parameter_tree, hf_rtps_durability, tvb, offset, 4,
                        little_endian ? ENC_LITTLE_ENDIAN : ENC_BIG_ENDIAN);
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
      rtps_util_add_durability_service_qos(rtps_parameter_tree, tvb, offset, little_endian);
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
      proto_tree_add_item(rtps_parameter_tree, hf_rtps_ownership, tvb, offset, 4,
                        little_endian ? ENC_LITTLE_ENDIAN : ENC_BIG_ENDIAN);
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
      proto_tree_add_item(rtps_parameter_tree, hf_rtps_presentation_access_scope, tvb, offset, 4,
                        little_endian ? ENC_LITTLE_ENDIAN : ENC_BIG_ENDIAN);
      proto_tree_add_item(rtps_parameter_tree, hf_rtps_presentation_coherent_access, tvb, offset+4, 1, ENC_NA );
      proto_tree_add_item(rtps_parameter_tree, hf_rtps_presentation_ordered_access, tvb, offset+5, 1, ENC_NA );
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
      rtps_util_add_ntp_time(rtps_parameter_tree, tvb, offset, little_endian, hf_rtps_deadline_period);
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
      proto_tree_add_item(rtps_parameter_tree, hf_rtps_destination_order, tvb, offset, 4,
                        little_endian ? ENC_LITTLE_ENDIAN : ENC_BIG_ENDIAN);
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
      rtps_util_add_ntp_time(rtps_parameter_tree, tvb, offset,
                    little_endian, hf_rtps_latency_budget_duration);
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
      rtps_util_add_seq_string(rtps_parameter_tree, tvb, offset, little_endian,
                    param_length, hf_rtps_param_partition_num, hf_rtps_param_partition, "name");
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
      rtps_util_add_ntp_time(rtps_parameter_tree, tvb, offset, little_endian,
                             hf_rtps_lifespan_duration);
      break;

    /* 0...2...........7...............15.............23...............31
     * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     * | PID_USER_DATA                 |             length            |
     * +---------------+---------------+---------------+---------------+
     * |    unsigned long     sequence_size                            |
     * +---------------+---------------+---------------+---------------+
     * |   octect[0]   |   octet[1]    |   octect[2]   |   octet[3]    |
     * +---------------+---------------+---------------+---------------+
     * |                              ...                              |
     * +---------------+---------------+---------------+---------------+
     */
    case PID_USER_DATA:
      ENSURE_LENGTH(4);
      rtps_util_add_seq_octets(rtps_parameter_tree, pinfo, tvb, offset,
                    little_endian, param_length, hf_rtps_param_user_data);
      break;

    /* 0...2...........7...............15.............23...............31
     * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     * | PID_GROUP_DATA                |             length            |
     * +---------------+---------------+---------------+---------------+
     * |    unsigned long     sequence_size                            |
     * +---------------+---------------+---------------+---------------+
     * |   octect[0]   |   octet[1]    |   octect[2]   |   octet[3]    |
     * +---------------+---------------+---------------+---------------+
     * |                              ...                              |
     * +---------------+---------------+---------------+---------------+
     */
    case PID_GROUP_DATA:
      ENSURE_LENGTH(4);
      rtps_util_add_seq_octets(rtps_parameter_tree, pinfo, tvb, offset,
                    little_endian, param_length, hf_rtps_param_group_data);
      break;

    /* 0...2...........7...............15.............23...............31
     * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     * | PID_TOPIC_DATA                |             length            |
     * +---------------+---------------+---------------+---------------+
     * |    unsigned long     sequence_size                            |
     * +---------------+---------------+---------------+---------------+
     * |   octect[0]   |   octet[1]    |   octect[2]   |   octet[3]    |
     * +---------------+---------------+---------------+---------------+
     * |                              ...                              |
     * +---------------+---------------+---------------+---------------+
     */
    case PID_TOPIC_DATA:
      ENSURE_LENGTH(4);
      rtps_util_add_seq_octets(rtps_parameter_tree, pinfo, tvb, offset,
                    little_endian, param_length, hf_rtps_param_topic_data);
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
      rtps_util_add_locator_t(rtps_parameter_tree, pinfo, tvb,
                    offset, little_endian, "locator");
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
      rtps_util_add_locator_t(rtps_parameter_tree, pinfo, tvb,
                    offset, little_endian, "locator");
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
      rtps_util_add_locator_t(rtps_parameter_tree, pinfo, tvb, offset,
                              little_endian, "locator");
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
      rtps_util_add_locator_t(rtps_parameter_tree, pinfo, tvb, offset,
                              little_endian, "locator");
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
      rtps_util_add_locator_t(rtps_parameter_tree, pinfo, tvb,
                    offset, little_endian, "locator");
      break;

    /* 0...2...........7...............15.............23...............31
     * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     * | PID_PARTICIPANT_MANUAL_LIVE...|            0x0004             |
     * +---------------+---------------+---------------+---------------+
     * |    long              livelinessEpoch                          |
     * +---------------+---------------+---------------+---------------+
     */
    case PID_PARTICIPANT_BUILTIN_ENDPOINTS:
      ENSURE_LENGTH(4);
      proto_tree_add_item(rtps_parameter_tree, hf_rtps_participant_builtin_endpoints, tvb, offset, 4,
                        little_endian ? ENC_LITTLE_ENDIAN : ENC_BIG_ENDIAN);
      break;

    case PID_PARTICIPANT_MANUAL_LIVELINESS_COUNT:
      ENSURE_LENGTH(4);
      proto_tree_add_item(rtps_parameter_tree, hf_rtps_participant_manual_liveliness_count, tvb, offset, 4,
                        little_endian ? ENC_LITTLE_ENDIAN : ENC_BIG_ENDIAN);
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
      proto_tree_add_item(rtps_parameter_tree, hf_rtps_history_kind, tvb, offset, 4,
                        little_endian ? ENC_LITTLE_ENDIAN : ENC_BIG_ENDIAN);
      proto_tree_add_item(rtps_parameter_tree, hf_rtps_history_depth, tvb, offset+4, 4,
                        little_endian ? ENC_LITTLE_ENDIAN : ENC_BIG_ENDIAN);
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
      ti = proto_tree_add_text(rtps_parameter_tree, tvb, offset, 12, "Resource Limit");
      subtree = proto_item_add_subtree(ti, ett_rtps_resource_limit);
      proto_tree_add_item(subtree, hf_rtps_resource_limit_max_samples, tvb, offset, 4, little_endian ? ENC_LITTLE_ENDIAN : ENC_BIG_ENDIAN);
      proto_tree_add_item(subtree, hf_rtps_resource_limit_max_instances, tvb, offset+4, 4, little_endian ? ENC_LITTLE_ENDIAN : ENC_BIG_ENDIAN);
      proto_tree_add_item(subtree, hf_rtps_resource_limit_max_samples_per_instances, tvb, offset+8, 4, little_endian ? ENC_LITTLE_ENDIAN : ENC_BIG_ENDIAN);
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
      temp_offset = rtps_util_add_string(rtps_parameter_tree, tvb, temp_offset,
                    hf_rtps_param_content_filter_name, little_endian);
      temp_offset = rtps_util_add_string(rtps_parameter_tree, tvb, temp_offset,
                    hf_rtps_param_related_topic_name, little_endian);
      temp_offset = rtps_util_add_string(rtps_parameter_tree, tvb, temp_offset,
                    hf_rtps_param_filter_name, little_endian);
      temp_offset = rtps_util_add_string(rtps_parameter_tree, tvb, temp_offset,
                    hf_rtps_param_filter_expression, little_endian);
      /*temp_offset = */rtps_util_add_seq_string(rtps_parameter_tree, tvb, temp_offset,
                    little_endian, param_length, hf_rtps_param_filter_parameters_num,
                    hf_rtps_param_filter_parameters, "filterParameters");
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
        guint32 prev_offset, temp_offset, prop_size;
        const guint8 *propName, *propValue;
        guint32 seq_size = NEXT_guint32(tvb, offset, little_endian);
        proto_item_append_text( parameter_item, " (%d properties)", seq_size );
        if (seq_size > 0) {
          proto_tree_add_text(rtps_parameter_tree, tvb, offset, 0,
                    /*  123456789012345678901234567890|123456789012345678901234567890 */
                    "        Property Name         |       Property Value");

          proto_tree_add_text(rtps_parameter_tree, tvb, offset, 0,
                    /*  123456789012345678901234567890|123456789012345678901234567890 */
                    "------------------------------|------------------------------");

          temp_offset = offset+4;
          while(seq_size-- > 0) {
            prev_offset = temp_offset;
            prop_size = NEXT_guint32(tvb, temp_offset, little_endian);
            if (prop_size > 0) {
              propName = tvb_get_string_enc(wmem_packet_scope(), tvb, temp_offset+4, prop_size, ENC_ASCII);
            } else {
              propName = (const guint8 *)"";
            }
            /* NDDS align strings at 4-bytes word. */
            temp_offset += (4 + ((prop_size + 3) & 0xfffffffc));

            prop_size = NEXT_guint32(tvb, temp_offset, little_endian);
            if (prop_size > 0) {
              propValue = tvb_get_string_enc(wmem_packet_scope(), tvb, temp_offset+4, prop_size, ENC_ASCII);
            } else {
              propValue = (const guint8 *)"";
            }
            /* NDDS align strings at 4-bytes word. */
            temp_offset += (4 + ((prop_size + 3) & 0xfffffffc));

            proto_tree_add_text(rtps_parameter_tree, tvb, prev_offset,
                        temp_offset - prev_offset, "%-29s | %-29s",
                        propName,
                        propValue);
          }
        }
      }
      break;

    /* 0...2...........7...............15.............23...............31
     * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     * | PID_FILTER_SIGNATURE          |            length             |
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
    case PID_FILTER_SIGNATURE: {
      guint32 temp_offset = offset;
      guint32 prev_offset;
      guint32 fs_elem;
      guint32 fs[4];
      ENSURE_LENGTH(8);

      /* Dissect filter bitmap */
      temp_offset = rtps_util_add_seq_ulong(rtps_parameter_tree, tvb, offset,
                        hf_rtps_filter_bitmap, little_endian, param_length, "filterBitmap");

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
          proto_tree_add_text(rtps_parameter_tree, tvb, prev_offset,
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
      rtps_util_add_seq_number(rtps_parameter_tree, tvb, offset,
                    little_endian, "sequenceNumber");
      break;

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
      rtps_util_add_typecode(rtps_parameter_tree, tvb, offset, little_endian,
                    0,      /* indent level */
                    0,      /* isPointer */
                    -1,     /* bitfield */
                    0,      /* isKey */
                    offset,
                    NULL,   /* name */
                    -1,     /* not a seq field */
                    NULL,   /* not an array */
                    0);     /* ndds 4.0 hack: init to false */
      break;

    /* 0...2...........7...............15.............23...............31
     * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     * | PID_PARTICIPANT_GUID          |            0x000c             |
     * +---------------+---------------+---------------+---------------+
     * |    guid[0]    |    guid[1]    |    guid[2]    |   guid[3]     |
     * +---------------+---------------+---------------+---------------+
     * |    guid[4]    |    guid[5]    |    guid[6]    |   guid[7]     |
     * +---------------+---------------+---------------+---------------+
     * |    guid[8]    |    guid[9]    |    guid[10]   |   guid[11]    |
     * +---------------+---------------+---------------+---------------+
     */
    case PID_PARTICIPANT_GUID:
      if (version < 0x0200) {
        ENSURE_LENGTH(12);
        rtps_util_add_generic_guid_v1(rtps_parameter_tree, tvb, offset,
                    hf_rtps_participant_guid, hf_rtps_param_host_id, hf_rtps_param_app_id,
                    hf_rtps_param_instance_id, hf_rtps_param_app_kind,
                    hf_rtps_param_entity, hf_rtps_param_entity_key, hf_rtps_param_hf_entity_kind);
      } else {
        ENSURE_LENGTH(16);
        rtps_util_add_generic_guid_v2(rtps_parameter_tree, tvb, offset,
                    hf_rtps_participant_guid, hf_rtps_param_host_id, hf_rtps_param_app_id,
                    hf_rtps_param_instance_id, hf_rtps_param_app_kind, hf_rtps_param_counter,
                    hf_rtps_param_entity, hf_rtps_param_entity_key, hf_rtps_param_hf_entity_kind);
      }
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
      rtps_util_add_generic_entity_id(rtps_parameter_tree, tvb, offset,  "Participant entity ID",
                                      hf_rtps_param_entity, hf_rtps_param_entity_key,
                                      hf_rtps_param_hf_entity_kind, ett_rtps_entity);

      break;

    /* 0...2...........7...............15.............23...............31
     * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     * | PID_GROUP_GUID                |            0x000c             |
     * +---------------+---------------+---------------+---------------+
     * |    guid[0]    |    guid[1]    |    guid[2]    |   guid[3]     |
     * +---------------+---------------+---------------+---------------+
     * |    guid[4]    |    guid[5]    |    guid[6]    |   guid[7]     |
     * +---------------+---------------+---------------+---------------+
     * |    guid[8]    |    guid[9]    |    guid[10]   |   guid[11]    |
     * +---------------+---------------+---------------+---------------+
     */
    case PID_GROUP_GUID:
      if (version < 0x0200) {
        ENSURE_LENGTH(12);
        rtps_util_add_generic_guid_v1(rtps_parameter_tree, tvb, offset,
                    hf_rtps_group_guid, hf_rtps_param_host_id, hf_rtps_param_app_id,
                    hf_rtps_param_instance_id, hf_rtps_param_app_kind,
                    hf_rtps_param_entity, hf_rtps_param_entity_key, hf_rtps_param_hf_entity_kind);
      } else {
        ENSURE_LENGTH(16);
        rtps_util_add_generic_guid_v2(rtps_parameter_tree, tvb, offset,
                    hf_rtps_group_guid, hf_rtps_param_host_id, hf_rtps_param_app_id,
                    hf_rtps_param_instance_id, hf_rtps_param_app_kind, hf_rtps_param_counter,
                    hf_rtps_param_entity, hf_rtps_param_entity_key, hf_rtps_param_hf_entity_kind);
      }
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
      rtps_util_add_generic_entity_id(rtps_parameter_tree, tvb, offset, "Group entity ID",
                                      hf_rtps_param_entity, hf_rtps_param_entity_key,
                                      hf_rtps_param_hf_entity_kind, ett_rtps_entity);
      break;

    /* ==================================================================
     * Here are all the deprecated items.
     */

    case PID_PERSISTENCE:
      ENSURE_LENGTH(8);
      rtps_util_add_ntp_time(rtps_parameter_tree, tvb, offset, little_endian,
                        hf_rtps_persistence);
      break;

    case PID_TYPE_CHECKSUM:
      ENSURE_LENGTH(4);
      proto_tree_add_item(rtps_parameter_tree, hf_rtps_type_checksum, tvb, offset, 4,
                          little_endian ? ENC_LITTLE_ENDIAN : ENC_BIG_ENDIAN);
      break;

    case PID_EXPECTS_ACK:
      ENSURE_LENGTH(1);
      proto_tree_add_item(rtps_parameter_tree, hf_rtps_expects_ack, tvb, offset, 1, ENC_NA );
      break;

    case PID_MANAGER_KEY: {
      int i = 0;
      guint32 manager_key;

      ti = proto_tree_add_text(rtps_parameter_tree, tvb, offset, param_length, "Manager Keys");
      subtree = proto_item_add_subtree(ti, ett_rtps_manager_key);

      while (param_length >= 4) {
        manager_key = NEXT_guint32(tvb, offset, little_endian);
        proto_tree_add_uint_format(subtree, hf_rtps_manager_key, tvb, offset, 4,
                                    manager_key, "Key[%d]: 0x%X", i, manager_key);

        ++i;
        offset +=4;
        param_length -= 4; /* decrement count */
      }
      break;
      }

    case PID_RECV_QUEUE_SIZE:
    case PID_SEND_QUEUE_SIZE:
      ENSURE_LENGTH(4);
      proto_tree_add_item(rtps_parameter_tree, hf_rtps_queue_size, tvb, offset, 4, little_endian ? ENC_LITTLE_ENDIAN : ENC_BIG_ENDIAN);
      break;

    case PID_VARGAPPS_SEQUENCE_NUMBER_LAST:
      ENSURE_LENGTH(4);
      rtps_util_add_seq_number(rtps_parameter_tree, tvb, offset, little_endian, "sequenceNumberLast");
      break;

    case PID_SENTINEL:
      /* PID_SENTINEL should ignore any value of parameter length */
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
      expert_add_info(pinfo, parameter_item, &ei_rtps_parameter_not_decoded);

    case PID_PAD:
      if (param_length > 0) {
        proto_tree_add_text(rtps_parameter_tree, tvb, offset, param_length, "parameterData");
      }
      break;

    default:
      return FALSE;
  }

  return TRUE;
}

static gboolean dissect_parameter_sequence_v2(proto_tree *rtps_parameter_tree, packet_info *pinfo, tvbuff_t *tvb,
                        proto_item* parameter_item, proto_item*  param_len_item, gint offset,
                        gboolean little_endian, int param_length,
                        guint16 parameter, guint32 *pStatusInfo, guint16 vendor_id) {
  proto_item *ti;

  switch(parameter) {
    /* 0...2...........7...............15.............23...............31
     * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     * | PID_STATUS_INFO               |            0x0004             |
     * +---------------+---------------+---------------+---------------+
     * |    long              statusInfo                               |
     * +---------------+---------------+---------------+---------------+
     */
    case PID_STATUS_INFO:
      ENSURE_LENGTH(4);
      proto_tree_add_item(rtps_parameter_tree, hf_rtps_param_status_info, tvb, offset, 4, little_endian ? ENC_LITTLE_ENDIAN : ENC_BIG_ENDIAN);

      if (pStatusInfo != NULL) {
        *pStatusInfo = NEXT_guint32(tvb, offset, little_endian);
      }
      break;

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
    ENSURE_LENGTH(16);
    rtps_util_add_guid_prefix_v2(rtps_parameter_tree, tvb, offset, hf_rtps_sm_guid_prefix,
                    hf_rtps_sm_host_id, hf_rtps_sm_app_id, hf_rtps_sm_counter, "guidPrefix");
    rtps_util_add_entity_id(rtps_parameter_tree, tvb, offset+12, hf_rtps_sm_entity_id,
                    hf_rtps_sm_entity_id_key, hf_rtps_sm_entity_id_kind, ett_rtps_entity,
                    "guidSuffix", NULL);
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
    ti = proto_tree_add_text(rtps_parameter_tree, tvb, offset, param_length, "guid: ");
    for (i = 0; i < param_length; ++i) {
      guidPart = tvb_get_guint8(tvb, offset+i);
      proto_item_append_text(ti, "%02x", guidPart);
      if (( ((i+1) % 4) == 0 ) && (i != param_length-1) )
        proto_item_append_text(ti, ":");
    }
    break;
    }

    /* 0...2...........7...............15.............23...............31
     * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     * | PID_TRANSPORT_PRIORITY        |            0x0004             |
     * +---------------+---------------+---------------+---------------+
     * |    unsigned long     value                                    |
     * +---------------+---------------+---------------+---------------+
     */
    case PID_TRANSPORT_PRIORITY:
      ENSURE_LENGTH(4);
      proto_tree_add_item(rtps_parameter_tree, hf_rtps_param_transport_priority, tvb, offset, 4,
                          little_endian ? ENC_LITTLE_ENDIAN : ENC_BIG_ENDIAN);
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
      temp_offset = rtps_util_add_seq_ulong(rtps_parameter_tree, tvb, offset,
                    hf_rtps_filter_bitmap, little_endian, param_length, "filterBitmap");

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
     * | PID_BUILTIN_ENDPOINT_SET      |            length             |
     * +---------------+---------------+---------------+---------------+
     * |    long              value                                    |
     * +---------------+---------------+---------------+---------------+
     */
    case PID_BUILTIN_ENDPOINT_SET:
      ENSURE_LENGTH(4);
      proto_tree_add_item(rtps_parameter_tree, hf_rtps_param_builtin_endpoint_set, tvb, offset, 4,
                          little_endian ? ENC_LITTLE_ENDIAN : ENC_BIG_ENDIAN);
      break;

    /* 0...2...........7...............15.............23...............31
     * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     * | PID_TYPE_MAX_SIZE_SERIALIZED  |            length             |
     * +---------------+---------------+---------------+---------------+
     * |    long              value                                    |
     * +---------------+---------------+---------------+---------------+
     */
    case PID_TYPE_MAX_SIZE_SERIALIZED:
      ENSURE_LENGTH(4);
      proto_tree_add_item(rtps_parameter_tree, hf_rtps_param_type_max_size_serialized, tvb, offset, 4,
                          little_endian ? ENC_LITTLE_ENDIAN : ENC_BIG_ENDIAN);
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
      rtps_util_add_guid_prefix_v2(rtps_parameter_tree, tvb, offset, hf_rtps_sm_guid_prefix,
                    hf_rtps_sm_host_id, hf_rtps_sm_app_id, hf_rtps_sm_counter, "virtualGUIDPrefix");
      rtps_util_add_entity_id(rtps_parameter_tree, tvb, offset+12, hf_rtps_sm_entity_id,
                    hf_rtps_sm_entity_id_key, hf_rtps_sm_entity_id_kind, ett_rtps_entity,
                    "virtualGUIDSuffix", NULL);

      /* Sequence number */
      rtps_util_add_seq_number(rtps_parameter_tree, tvb, offset+16,
                            little_endian, "virtualSeqNumber");
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
      rtps_util_add_string(rtps_parameter_tree, tvb, offset, hf_rtps_param_entity_name, little_endian);
      break;

    /* 0...2...........7...............15.............23...............31
     * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     * | PID_ENDPOINT_GUID             |            0x0010             |
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
    case PID_ENDPOINT_GUID:
      ENSURE_LENGTH(16);
      rtps_util_add_generic_guid_v2(rtps_parameter_tree, tvb, offset,
                    hf_rtps_endpoint_guid, hf_rtps_param_host_id, hf_rtps_param_app_id,
                    hf_rtps_param_instance_id, hf_rtps_param_app_kind, hf_rtps_param_counter,
                    hf_rtps_param_entity, hf_rtps_param_entity_key, hf_rtps_param_hf_entity_kind);
      break;

    default:
      /* The following PIDS are vendor-specific */
      if (vendor_id == RTPS_VENDOR_RTI_DDS) {
        switch(parameter) {
          /* 0...2...........7...............15.............23...............31
           * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           * | PID_PRODUCT_VERSION           |            length             |
           * +---------------+---------------+---------------+---------------+
           * | uint8 major   | uint8 minor   |    N O T    U S E D           |
           * +---------------+---------------+---------------+---------------+
           */
          case PID_PRODUCT_VERSION: {
            guint8 major, minor, release, revision;

            ENSURE_LENGTH(4);
            major = tvb_get_guint8(tvb, offset);
            minor = tvb_get_guint8(tvb, offset+1);
            release = tvb_get_guint8(tvb, offset+2);
            revision = tvb_get_guint8(tvb, offset+3);
            proto_tree_add_text(rtps_parameter_tree, tvb, offset, param_length,
                        "productVersion: %d.%d%c rev%d",
                        major, minor, release, revision);
            break;
          }

          /* 0...2...........7...............15.............23...............31
           * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           * | PID_PLUGIN_PROMISCUITY_KIND   |            length             |
           * +---------------+---------------+---------------+---------------+
           * | short  value                  |                               |
           * +---------------+---------------+---------------+---------------+
           */
          case PID_PLUGIN_PROMISCUITY_KIND:
            ENSURE_LENGTH(4);
            proto_tree_add_item(rtps_parameter_tree, hf_rtps_param_plugin_promiscuity_kind, tvb, offset, 4,
                          little_endian ? ENC_LITTLE_ENDIAN : ENC_BIG_ENDIAN);
            break;

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
              rtps_util_add_guid_prefix_v2(rtps_parameter_tree, tvb, offset,
                    hf_rtps_sm_guid_prefix, hf_rtps_sm_host_id, hf_rtps_sm_app_id,
                    hf_rtps_sm_counter, "virtualGUIDPrefix");
              rtps_util_add_entity_id(rtps_parameter_tree, tvb, offset+12,
                    hf_rtps_sm_entity_id, hf_rtps_sm_entity_id_key, hf_rtps_sm_entity_id_kind,
                    ett_rtps_entity, "virtualGUIDSuffix", NULL);
              break;


            /* 0...2...........7...............15.............23...............31
             * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
             * | PID_SERVICE_KIND              |            length             |
             * +---------------+---------------+---------------+---------------+
             * | long    value                                                 |
             * +---------------+---------------+---------------+---------------+
             */
            case PID_SERVICE_KIND:
              ENSURE_LENGTH(4);
              proto_tree_add_item(rtps_parameter_tree, hf_rtps_param_service_kind, tvb, offset, 4,
                          little_endian ? ENC_LITTLE_ENDIAN : ENC_BIG_ENDIAN);
              break;

            /* 0...2...........7...............15.............23...............31
             * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
             * | PID_TYPECODE_RTPS2            |            length             |
             * +---------------+---------------+---------------+---------------+
             * |                                                               |
             * +                    Type code description                      +
             * |                                                               |
             * +---------------+---------------+---------------+---------------+
             */
            case PID_TYPECODE_RTPS2:
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
              proto_tree_add_item(rtps_parameter_tree, hf_rtps_disable_positive_ack, tvb, offset, 1, ENC_NA );
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
              guint32 number_of_channels, ch;
              proto_tree *channel_tree;
              proto_item *ti_channel;
              char temp_buff[20];
              gint old_offset;
              guint32 off = offset;

              ENSURE_LENGTH(4);
              number_of_channels = NEXT_guint32(tvb, off, little_endian);
              proto_item_append_text( parameter_item, " (%d channels)", number_of_channels );
              proto_tree_add_int(rtps_parameter_tree, hf_rtps_locator_filter_list_num_channels, tvb, off, 4, number_of_channels );
              off += 4;

              if (number_of_channels == 0) {
                /* Do not dissect the rest */
                break;
              }

              /* filter name */
              off = rtps_util_add_string(rtps_parameter_tree, tvb, off, hf_rtps_locator_filter_list_filter_name, little_endian);

              /* Foreach channel... */
              for (ch = 0; ch < number_of_channels; ++ch) {
                g_snprintf(temp_buff, 20, "Channel[%u]", ch);
                old_offset = off;
                ti_channel = proto_tree_add_text(rtps_parameter_tree, tvb, off, 0, "Channel[%u]", ch);
                channel_tree = proto_item_add_subtree(ti_channel, ett_rtps_locator_filter_channel);

                off = rtps_util_add_locator_list(channel_tree, pinfo, tvb, off, temp_buff, little_endian);
                /* Filter expression */
                off = rtps_util_add_string(rtps_parameter_tree, tvb, off, hf_rtps_locator_filter_list_filter_exp, little_endian);

                /* Now we know the length of the channel data, set the length */
                proto_item_set_len(ti_channel, (off - old_offset));
              } /* End of for each channel */
              break;
            } /* End of case PID_LOCATOR_FILTER_LIST */

        } /* End of switch for parameters for vendor RTI */
      } /* End of branch vendor RTI */
      else if (vendor_id == RTPS_VENDOR_TOC) {
        switch(parameter) {
          /* 0...2...........7...............15.............23...............31
           * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           * | PID_TYPECODE_RTPS2            |            length             |
           * +---------------+---------------+---------------+---------------+
           * |                                                               |
           * +                    Type code description                      +
           * |                                                               |
           * +---------------+---------------+---------------+---------------+
           */
          case PID_TYPECODE_RTPS2:
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
      } else { /* End of branch vendor TOC */
        return FALSE;
      }
      break;
  }

  return TRUE;
}
#undef ENSURE_LENGTH

static gint dissect_parameter_sequence(proto_tree *tree, packet_info *pinfo, tvbuff_t *tvb,
                        gint offset, gboolean little_endian, int size, const char * label,
                        guint16 version, guint32 *pStatusInfo, guint16 vendor_id) {
  proto_item *ti, *param_item, *param_len_item = NULL;
  proto_tree *rtps_parameter_sequence_tree, *rtps_parameter_tree;
  guint16    parameter, param_length;
  gint       original_offset = offset;

  ti = proto_tree_add_text(tree, tvb, offset, -1, "%s:", label);
  rtps_parameter_sequence_tree = proto_item_add_subtree(ti, ett_rtps_parameter_sequence);

  /* Loop through all the parameters defined until PID_SENTINEL is found */
  for (;;) {
    size -= offset - original_offset;
    if (size < 4) {
      expert_add_info_format(pinfo, (param_len_item == NULL) ? ti : param_len_item, &ei_rtps_parameter_value_invalid, "ERROR: not enough bytes to read the next parameter");
      return 0;
    }
    original_offset = offset;

    /* Reads parameter and create the sub tree. At this point we don't know
     * the final string that will identify the node or its length. It will
     * be set later...
     */
    parameter = NEXT_guint16(tvb, offset, little_endian);
    if (version < 0x0200) {
      param_item = proto_tree_add_text(rtps_parameter_sequence_tree, tvb, offset, -1,
                        "%s", val_to_str(parameter, parameter_id_vals, "Unknown (0x%04x)"));
      rtps_parameter_tree = proto_item_add_subtree(param_item, ett_rtps_parameter);

      proto_tree_add_uint(rtps_parameter_tree, hf_rtps_parameter_id, tvb, offset, 2, parameter);
    } else {
      param_item = proto_tree_add_text(rtps_parameter_sequence_tree, tvb, offset, -1,
                        "%s", val_to_str(parameter, parameter_id_v2_vals, "Unknown (0x%04x)"));
      rtps_parameter_tree = proto_item_add_subtree(param_item, ett_rtps_parameter);

      proto_tree_add_uint(rtps_parameter_tree, hf_rtps_parameter_id_v2, tvb, offset, 2, parameter);
    }
    offset += 2;

    if (parameter == PID_SENTINEL) {
        /* PID_SENTINEL closes the parameter list, (length is ignored) */
        return offset +2;
    }

    /* parameter length */
    param_length = NEXT_guint16(tvb, offset, little_endian);
    param_len_item = proto_tree_add_item(rtps_parameter_tree, hf_rtps_parameter_length,
                        tvb, offset, 2, little_endian ? ENC_LITTLE_ENDIAN : ENC_BIG_ENDIAN);
    offset += 2;

    /* Make sure we have enough bytes for the param value */
    if ((size-4 < param_length) &&
        (parameter != PID_SENTINEL)) {
      expert_add_info_format(pinfo, param_len_item, &ei_rtps_parameter_value_invalid, "Not enough bytes to read the parameter value");
      return 0;
    }

    /* Sets the end of this item (now we know it!) */
    proto_item_set_len(param_item, param_length+4);

    if (!dissect_parameter_sequence_v1(rtps_parameter_tree, pinfo, tvb, param_item, param_len_item,
                                    offset, little_endian, size, param_length, parameter, version)) {
      if ((version < 0x0200) ||
          !dissect_parameter_sequence_v2(rtps_parameter_tree, pinfo, tvb, param_item, param_len_item,
                                      offset, little_endian, param_length, parameter,
                                      pStatusInfo, vendor_id)) {
        if (param_length > 0) {
          proto_tree_add_text(rtps_parameter_tree, tvb, offset, param_length,
                        "parameterData");
        }
      }
    }

    offset += param_length;
  }
  return offset;
}


gboolean rtps_is_ping(tvbuff_t *tvb, packet_info *pinfo, gint offset)
{
  gboolean is_ping = FALSE;

  if (!tvb_strneql(tvb, offset, "NDDSPING", 8))
    is_ping = TRUE;

  if (is_ping)
    col_set_str(pinfo->cinfo, COL_INFO, "PING");

  return is_ping;
}

/* *********************************************************************** */
/* * Serialized data dissector                                           * */
/* *********************************************************************** */
/* Note: the encapsulation header is ALWAYS big endian, then the encapsulation
 * type specified the type of endianess of the payload.
 */
static void dissect_serialized_data(proto_tree *tree, packet_info *pinfo, tvbuff_t *tvb, gint offset,
                        int  size, const char * label, guint16 vendor_id) {
  proto_item * ti;
  proto_tree * rtps_parameter_sequence_tree;
  guint16 encapsulation_id;
  gboolean encapsulation_little_endian = FALSE;

  /* Creates the sub-tree */
  ti = proto_tree_add_text(tree, tvb, offset, -1, "%s", label);
  rtps_parameter_sequence_tree = proto_item_add_subtree(ti, ett_rtps_serialized_data);

  /* Encapsulation ID */
  encapsulation_id =  NEXT_guint16(tvb, offset, FALSE);   /* Always big endian */
  proto_tree_add_uint(rtps_parameter_sequence_tree, hf_rtps_param_serialize_encap_kind, tvb, offset, 2, encapsulation_id);
  offset += 2;

  /* Sets the correct values for encapsulation_le */
  if (encapsulation_id == ENCAPSULATION_CDR_LE ||
      encapsulation_id == ENCAPSULATION_PL_CDR_LE) {
    encapsulation_little_endian = TRUE;
  }

  /* Encapsulation length (or option) */
  proto_tree_add_item(rtps_parameter_sequence_tree, hf_rtps_param_serialize_encap_len, tvb, offset, 2, ENC_BIG_ENDIAN);
  offset += 2;

  /* The payload */
  size -= 4;
  switch (encapsulation_id) {
    case ENCAPSULATION_CDR_LE:
    case ENCAPSULATION_CDR_BE:
          proto_tree_add_item(rtps_parameter_sequence_tree, hf_rtps_issue_data, tvb,
                        offset, size, encapsulation_little_endian ? ENC_LITTLE_ENDIAN : ENC_BIG_ENDIAN);
          break;

    case ENCAPSULATION_PL_CDR_LE:
    case ENCAPSULATION_PL_CDR_BE:
          dissect_parameter_sequence(rtps_parameter_sequence_tree, pinfo, tvb, offset,
                        encapsulation_little_endian, size, label, 0x0200, NULL, vendor_id);
          break;

    default:
          proto_tree_add_text(rtps_parameter_sequence_tree, tvb, offset,
                        size, "%s", label);
  }
}

/* *********************************************************************** */
/* *                                 P A D                               * */
/* *********************************************************************** */
void dissect_PAD(tvbuff_t *tvb,
                packet_info *pinfo,
                gint offset,
                guint8 flags,
                gboolean little_endian,
                int octets_to_next_header,
                proto_tree *tree) {
  /* 0...2...........7...............15.............23...............31
   * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   * |   PAD         |X|X|X|X|X|X|X|E|      octetsToNextHeader       |
   * +---------------+---------------+---------------+---------------+
   */
  proto_item* item;

  rtps_util_decode_flags(tree, tvb, offset + 1, flags, PAD_FLAGS);

  item = proto_tree_add_item(tree,
                          hf_rtps_sm_octets_to_next_header,
                          tvb,
                          offset + 2,
                          2,
                          little_endian ? ENC_LITTLE_ENDIAN : ENC_BIG_ENDIAN);
  if (octets_to_next_header != 0) {
    expert_add_info(pinfo, item, &ei_rtps_sm_octets_to_next_header_not_zero);
  }
}





/* *********************************************************************** */
/* *                               D A T A                               * */
/* *********************************************************************** */
static void dissect_DATA_v1(tvbuff_t *tvb, packet_info *pinfo, gint offset, guint8 flags,
                gboolean little_endian, int octets_to_next_header, proto_tree *tree) {
  /* RTPS 1.0/1.1:
   * 0...2...........7...............15.............23...............31
   * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   * |   DATA        |X|X|X|U|H|A|P|E|      octetsToNextHeader       |
   * +---------------+---------------+---------------+---------------+
   * | ObjectId readerObjectId                                       |
   * +---------------+---------------+---------------+---------------+
   * | ObjectId writerObjectId                                       |
   * +---------------+---------------+---------------+---------------+
   * | HostId hostId (iff H==1)                                      |
   * +---------------+---------------+---------------+---------------+
   * | AppId appId (iff H==1)                                        |
   * +---------------+---------------+---------------+---------------+
   * | ObjectId objectId                                             |
   * +---------------+---------------+---------------+---------------+
   * |                                                               |
   * + SequenceNumber writerSeqNumber                                +
   * |                                                               |
   * +---------------+---------------+---------------+---------------+
   * |                                                               |
   * ~ ParameterSequence parameters [only if P==1]                   ~
   * |                                                               |
   * +---------------+---------------+---------------+---------------+
   * Note: on RTPS 1.0, flag U is not present
   *
   * RTPS 1.2:
   * 0...2...........7...............15.............23...............31
   * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   * |   DATA        |X|X|U|Q|H|A|D|E|      octetsToNextHeader       |
   * +---------------+---------------+---------------+---------------+
   * | EntityId readerEntityId                                       |
   * +---------------+---------------+---------------+---------------+
   * | EntityId writerEntityId                                       |
   * +---------------+---------------+---------------+---------------+
   * |                                                               |
   * + KeyHashPrefix  keyHashPrefix [only if H==1]                   +
   * |                                                               |
   * +---------------+---------------+---------------+---------------+
   * | KeyHashSuffix  keyHashSuffix                                  |
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
   * Notes:
   *   - inlineQos is NEW
   *   - serializedData is equivalent to the old 'parameters'
   */
  int min_len;
  int is_builtin_entity = 0;    /* true=entityId.entityKind = built-in */
  gint old_offset = offset;
  guint32 wid;                  /* Writer EntityID */
  proto_item* octet_item;

  rtps_util_decode_flags(tree, tvb, offset + 1, flags, DATA_FLAGSv1);

  octet_item = proto_tree_add_item(tree, hf_rtps_sm_octets_to_next_header, tvb,
                        offset + 2, 2, little_endian ? ENC_LITTLE_ENDIAN : ENC_BIG_ENDIAN);

  /* Calculates the minimum length for this submessage */
  min_len = 20;
  if ((flags & FLAG_DATA_H) != 0) min_len += 8;
  if ((flags & FLAG_DATA_Q) != 0) min_len += 4;
  if ((flags & FLAG_DATA_D) != 0) min_len += 4;

  if (octets_to_next_header < min_len) {
    expert_add_info_format(pinfo, octet_item, &ei_rtps_sm_octets_to_next_header_error, "(Error: should be >= %u)", min_len);
    return;
  }

  offset += 4;

  /* readerEntityId */
  is_builtin_entity |= rtps_util_add_entity_id(tree, tvb, offset,
                        hf_rtps_sm_rdentity_id, hf_rtps_sm_rdentity_id_key, hf_rtps_sm_rdentity_id_kind,
                        ett_rtps_rdentity, "readerEntityId", NULL);
  offset += 4;

  /* writerEntityId */
  is_builtin_entity |= rtps_util_add_entity_id(tree, tvb, offset,
                        hf_rtps_sm_wrentity_id, hf_rtps_sm_wrentity_id_key, hf_rtps_sm_wrentity_id_kind,
                        ett_rtps_wrentity, "writerEntityId", &wid);
  offset += 4;

  /* Checks for predefined declarations
   *
   *       writerEntityId value                 | A flag | Extra
   * -------------------------------------------|--------|-------------
   * ENTITYID_BUILTIN_SUBSCRIPTIONS_WRITER      |    1   | r+
   * ENTITYID_BUILTIN_SUBSCRIPTIONS_WRITER      |    0   | r-
   * ENTITYID_BUILTIN_PUBLICATIONS_WRITER       |    1   | w+
   * ENTITYID_BUILTIN_PUBLICATIONS_WRITER       |    0   | w-
   * ENTITYID_BUILTIN_SDP_PARTICIPANT_WRITER    |    1   | p+
   * ENTITYID_BUILTIN_SDP_PARTICIPANT_WRITER    |    0   | p-   (*)
   * ENTITYID_BUILTIN_TOPIC_WRITER              |    1   | t+   (*)
   * ENTITYID_BUILTIN_TOPIC_WRITER              |    0   | t-   (*)
   *
   * Note (*): Currently NDDS does not publish those values
   */
  if (wid == ENTITYID_BUILTIN_PUBLICATIONS_WRITER && (flags & FLAG_DATA_A) != 0) {
      col_append_str(pinfo->cinfo, COL_INFO, SM_EXTRA_WPLUS);
  } else if (wid == ENTITYID_BUILTIN_PUBLICATIONS_WRITER && (flags & FLAG_DATA_A) == 0) {
      col_append_str(pinfo->cinfo, COL_INFO, SM_EXTRA_WMINUS);
  } else if (wid == ENTITYID_BUILTIN_SUBSCRIPTIONS_WRITER && (flags & FLAG_DATA_A) != 0) {
      col_append_str(pinfo->cinfo, COL_INFO, SM_EXTRA_RPLUS);
  } else if (wid == ENTITYID_BUILTIN_SUBSCRIPTIONS_WRITER && (flags & FLAG_DATA_A) == 0) {
      col_append_str(pinfo->cinfo, COL_INFO, SM_EXTRA_RMINUS);
  } else if (wid == ENTITYID_BUILTIN_SDP_PARTICIPANT_WRITER && (flags & FLAG_DATA_A) != 0) {
      col_append_str(pinfo->cinfo, COL_INFO, SM_EXTRA_PPLUS);
  } else if (wid == ENTITYID_BUILTIN_SDP_PARTICIPANT_WRITER && (flags & FLAG_DATA_A) == 0) {
      col_append_str(pinfo->cinfo, COL_INFO, SM_EXTRA_PMINUS);
  } else if (wid == ENTITYID_BUILTIN_TOPIC_WRITER && (flags & FLAG_DATA_A) != 0) {
      col_append_str(pinfo->cinfo, COL_INFO, SM_EXTRA_TPLUS);
  } else if (wid == ENTITYID_BUILTIN_TOPIC_WRITER && (flags & FLAG_DATA_A) == 0) {
      col_append_str(pinfo->cinfo, COL_INFO, SM_EXTRA_TMINUS);
  }

  /* If flag H is defined, read the HostId and AppId fields */
  if ((flags & FLAG_DATA_H) != 0) {
    rtps_util_add_guid_prefix_v1(tree, tvb, offset,
                        hf_rtps_sm_guid_prefix, hf_rtps_sm_host_id, hf_rtps_sm_app_id,
                        hf_rtps_sm_instance_id, hf_rtps_sm_app_kind,
                        "keyHashPrefix");

    offset += 8;
  } else {
    /* Flag H not set, use hostId, appId from the packet header */
  }

  /* Complete the GUID by reading the Object ID */
  rtps_util_add_entity_id(tree, tvb, offset, hf_rtps_sm_entity_id, hf_rtps_sm_entity_id_key,
                        hf_rtps_sm_entity_id_kind, ett_rtps_entity, "keyHashSuffix", NULL);
  offset += 4;

  /* Sequence number */
  rtps_util_add_seq_number(tree, tvb, offset, little_endian, "writerSeqNumber");
  offset += 8;

  /* InlineQos */
  if ((flags & FLAG_DATA_Q) != 0) {
    offset = dissect_parameter_sequence(tree, pinfo, tvb, offset,
                        little_endian, octets_to_next_header, "inlineQos",
                        0x0102, NULL, 0);
  }

  /* SerializedData */
  if ((flags & FLAG_DATA_D) != 0) {
    if (is_builtin_entity) {
      dissect_parameter_sequence(tree, pinfo, tvb, offset,
                        little_endian, octets_to_next_header, "serializedData",
                        0x0102, NULL, 0);
    } else {
      proto_tree_add_item(tree, hf_rtps_issue_data, tvb, offset,
                        octets_to_next_header - (offset - old_offset) + 4,
                        little_endian ? ENC_LITTLE_ENDIAN : ENC_BIG_ENDIAN);
    }
  }
}

static void dissect_DATA_v2(tvbuff_t *tvb, packet_info *pinfo, gint offset, guint8 flags,
                            gboolean little_endian, int octets_to_next_header, proto_tree *tree,
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
  proto_item* octet_item;

  rtps_util_decode_flags(tree, tvb, offset + 1, flags, DATA_FLAGSv2);

  octet_item = proto_tree_add_item(tree, hf_rtps_sm_octets_to_next_header, tvb,
                        offset + 2, 2, little_endian ? ENC_LITTLE_ENDIAN : ENC_BIG_ENDIAN);

  /* Calculates the minimum length for this submessage */
  min_len = 20;
  if ((flags & FLAG_DATA_Q_v2) != 0) min_len += 4;
  if ((flags & FLAG_DATA_D_v2) != 0) min_len += 4;
  if ((flags & FLAG_DATA_H) != 0) min_len += 12;

  if (octets_to_next_header < min_len) {
    expert_add_info_format(pinfo, octet_item, &ei_rtps_sm_octets_to_next_header_error, "(Error: should be >= %u)", min_len);
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
    info_summary_append_ex(pinfo, wid, status_info);
    return;
  }

  offset += 4;


  /* readerEntityId */
  rtps_util_add_entity_id(tree, tvb, offset, hf_rtps_sm_rdentity_id, hf_rtps_sm_rdentity_id_key,
                        hf_rtps_sm_rdentity_id_kind, ett_rtps_rdentity, "readerEntityId", NULL);
  offset += 4;

  /* writerEntityId */
  rtps_util_add_entity_id(tree, tvb, offset, hf_rtps_sm_wrentity_id, hf_rtps_sm_wrentity_id_key,
                        hf_rtps_sm_wrentity_id_kind, ett_rtps_wrentity, "writerEntityId", &wid);
  offset += 4;


  /* Sequence number */
  rtps_util_add_seq_number(tree, tvb, offset, little_endian, "writerSeqNumber");
  offset += 8;

  /* If flag H is defined, read the GUID Prefix */
  if ((flags & FLAG_DATA_H) != 0) {
    rtps_util_add_guid_prefix_v2(tree, tvb, offset, hf_rtps_sm_guid_prefix, hf_rtps_sm_host_id,
                        hf_rtps_sm_app_id, hf_rtps_sm_counter, "keyHashPrefix");

    offset += 12;
  } else {
    /* Flag H not set, use hostId, appId from the packet header */
  }

  /* Complete the GUID by reading the Object ID */
  rtps_util_add_entity_id(tree, tvb, offset, hf_rtps_sm_entity_id, hf_rtps_sm_entity_id_key,
                        hf_rtps_sm_entity_id_kind, ett_rtps_entity, "keyHashSuffix", NULL);
  offset += 4;

  if ((flags & FLAG_DATA_I) != 0) {
    proto_tree_add_item(tree, hf_rtps_data_status_info, tvb,
                        offset, 4, little_endian ? ENC_LITTLE_ENDIAN : ENC_BIG_ENDIAN);
    offset += 4;
  }

  /* InlineQos */
  if ((flags & FLAG_DATA_Q_v2) != 0) {
    offset = dissect_parameter_sequence(tree, pinfo, tvb, offset, little_endian,
                        octets_to_next_header - (offset - old_offset) + 4,
                        "inlineQos", 0x0200, NULL, vendor_id);
  }

  /* SerializedData */
  if ((flags & FLAG_DATA_D_v2) != 0) {
    dissect_serialized_data(tree, pinfo, tvb, offset,
                        octets_to_next_header - (offset - old_offset) + 4,
                        "serializedData", vendor_id);
  }
  info_summary_append_ex(pinfo, wid, status_info);
}

static void dissect_DATA_FRAG(tvbuff_t *tvb, packet_info *pinfo, gint offset, guint8 flags,
                gboolean little_endian, int octets_to_next_header, proto_tree *tree, guint16 vendor_id) {
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
  proto_item* octet_item;

  rtps_util_decode_flags(tree, tvb, offset + 1, flags, NOKEY_DATA_FRAG_FLAGS);

  octet_item = proto_tree_add_item(tree, hf_rtps_sm_octets_to_next_header, tvb,
                        offset + 2, 2, little_endian ? ENC_LITTLE_ENDIAN : ENC_BIG_ENDIAN);

  /* Calculates the minimum length for this submessage */
  min_len = 32;
  if ((flags & FLAG_DATA_FRAG_Q) != 0) min_len += 4;
  if ((flags & FLAG_DATA_FRAG_H) != 0) min_len += 12;

  if (octets_to_next_header < min_len) {
    expert_add_info_format(pinfo, octet_item, &ei_rtps_sm_octets_to_next_header_error, "(Error: should be >= %u)", min_len);
    return;
  }

  /* Skip decoding the entire packet if (tree == NULL)
   */
  if (tree == NULL) {
    return;
  }

  offset += 4;

  /* readerEntityId */
  rtps_util_add_entity_id(tree, tvb, offset, hf_rtps_sm_rdentity_id, hf_rtps_sm_rdentity_id_key,
                        hf_rtps_sm_rdentity_id_kind, ett_rtps_rdentity, "readerEntityId", NULL);
  offset += 4;

  /* writerEntityId */
  rtps_util_add_entity_id(tree, tvb, offset, hf_rtps_sm_wrentity_id, hf_rtps_sm_wrentity_id_key,
                        hf_rtps_sm_wrentity_id_kind, ett_rtps_wrentity, "writerEntityId", NULL);
  offset += 4;

  /* Sequence number */
  rtps_util_add_seq_number(tree, tvb, offset, little_endian, "writerSeqNumber");
  offset += 8;

  /* If flag H is defined, read the GUID Prefix */
  if ((flags & FLAG_DATA_H) != 0) {
    rtps_util_add_guid_prefix_v2(tree, tvb, offset, hf_rtps_sm_guid_prefix,
                    hf_rtps_sm_host_id, hf_rtps_sm_app_id, hf_rtps_sm_counter, "keyHashPrefix");
    offset += 12;
  } else {
    /* Flag H not set, use hostId, appId from the packet header */
  }

  /* Complete the GUID by reading the Object ID */
  rtps_util_add_entity_id(tree, tvb, offset, hf_rtps_sm_entity_id, hf_rtps_sm_entity_id_key,
                        hf_rtps_sm_entity_id_kind, ett_rtps_entity, "keyHashSuffix", NULL);
  offset += 4;


  /* Fragment number */
  proto_tree_add_item(tree, hf_rtps_data_frag_number, tvb,
                        offset, 4, little_endian ? ENC_LITTLE_ENDIAN : ENC_BIG_ENDIAN);
  offset += 4;

  /* Fragments in submessage */
  proto_tree_add_item(tree, hf_rtps_data_frag_num_fragments, tvb,
                        offset, 2, little_endian ? ENC_LITTLE_ENDIAN : ENC_BIG_ENDIAN);
  offset += 2;

  /* Fragment size */
  proto_tree_add_item(tree, hf_rtps_data_frag_size, tvb,
                        offset, 2, little_endian ? ENC_LITTLE_ENDIAN : ENC_BIG_ENDIAN);
  offset += 2;

  /* sampleSize */
  proto_tree_add_item(tree, hf_rtps_data_frag_sample_size, tvb,
                        offset, 4, little_endian ? ENC_LITTLE_ENDIAN : ENC_BIG_ENDIAN);
  offset += 4;

  /* InlineQos */
  if ((flags & FLAG_DATA_Q_v2) != 0) {
    offset = dissect_parameter_sequence(tree, pinfo, tvb, offset, little_endian,
                        octets_to_next_header - (offset - old_offset) + 4,
                        "inlineQos", 0x0200, NULL, vendor_id);
  }

  /* SerializedData */
  if ((flags & FLAG_DATA_D_v2) != 0) {
    dissect_serialized_data(tree, pinfo, tvb, offset,
                        octets_to_next_header - (offset - old_offset) + 4,
                        "serializedData", vendor_id);
  }
}


/* *********************************************************************** */
/* *                        N O K E Y _ D A T A                          * */
/* *********************************************************************** */
static void dissect_NOKEY_DATA(tvbuff_t *tvb, packet_info *pinfo, gint offset, guint8 flags,
                gboolean little_endian, int octets_to_next_header, proto_tree *tree,
                guint16 version, guint16 vendor_id) {
  /* RTPS 1.0/1.1:
   * 0...2...........7...............15.............23...............31
   * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   * |   ISSUE       |X|X|X|X|X|X|P|E|      octetsToNextHeader       |
   * +---------------+---------------+---------------+---------------+
   * | ObjectId readerObjectId                                       |
   * +---------------+---------------+---------------+---------------+
   * | ObjectId writerObjectId                                       |
   * +---------------+---------------+---------------+---------------+
   * |                                                               |
   * + SequenceNumber writerSeqNumber                                +
   * |                                                               |
   * +---------------+---------------+---------------+---------------+
   * |                                                               |
   * ~ ParameterSequence parameters [only if P==1]                   ~
   * |                                                               |
   * +---------------+---------------+---------------+---------------+
   * |                                                               |
   * ~ UserData issueData                                            ~
   * |                                                               |
   * +---------------+---------------+---------------+---------------+
   *
   * RTPS 1.2:
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
   * ~ SerializedData serializedData [only if D==0]                  ~
   * |                                                               |
   * +---------------+---------------+---------------+---------------+
   *
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
   * Notes:
   *   - inlineQos is equivalent to the old 'parameters'
   *   - serializedData is equivalent to the old 'issueData'
   */

  int  min_len;
  gint old_offset = offset;
  proto_item* octet_item;

  rtps_util_decode_flags(tree, tvb, offset + 1, flags, NOKEY_DATA_FLAGS);

  octet_item = proto_tree_add_item(tree, hf_rtps_sm_octets_to_next_header, tvb,
                        offset + 2, 2, little_endian ? ENC_LITTLE_ENDIAN : ENC_BIG_ENDIAN);

  /* Calculates the minimum length for this submessage */
  min_len = 16;
  if ((flags & FLAG_NOKEY_DATA_Q) != 0) min_len += 4;

  if (octets_to_next_header < min_len) {
    expert_add_info_format(pinfo, octet_item, &ei_rtps_sm_octets_to_next_header_error, "(Error: should be >= %u)", min_len);
    return;
  }

  offset += 4;

  /* readerEntityId */
  rtps_util_add_entity_id(tree, tvb, offset, hf_rtps_sm_rdentity_id, hf_rtps_sm_rdentity_id_key,
                        hf_rtps_sm_rdentity_id_kind, ett_rtps_rdentity, "readerEntityId", NULL);
  offset += 4;

  /* writerEntityId */
  rtps_util_add_entity_id(tree, tvb, offset, hf_rtps_sm_wrentity_id, hf_rtps_sm_wrentity_id_key,
                        hf_rtps_sm_wrentity_id_kind, ett_rtps_wrentity, "writerEntityId", NULL);
  offset += 4;

  /* Sequence number */
  rtps_util_add_seq_number(tree, tvb, offset, little_endian, "writerSeqNumber");
  offset += 8;

  /* Parameters */
  if ((flags & FLAG_NOKEY_DATA_Q) != 0) {
    offset = dissect_parameter_sequence(tree, pinfo, tvb, offset,
                        little_endian, octets_to_next_header, "inlineQos",
                        version, NULL, vendor_id);

  }

  /* Issue Data */
  if ((version < 0x0200) && (flags & FLAG_NOKEY_DATA_D) == 0) {
    proto_tree_add_item(tree, hf_rtps_issue_data, tvb, offset,
                         octets_to_next_header - (offset - old_offset) + 4,
                        little_endian ? ENC_LITTLE_ENDIAN : ENC_BIG_ENDIAN);
  }

  if ((version >= 0x0200) && (flags & FLAG_DATA_D_v2) != 0) {
    dissect_serialized_data(tree, pinfo, tvb, offset,
                        octets_to_next_header - (offset - old_offset) + 4,
                        "serializedData", vendor_id);
  }

}

/* *********************************************************************** */
/* *                    N O K E Y _ D A T A _ F R A G                    * */
/* *********************************************************************** */
static void dissect_NOKEY_DATA_FRAG(tvbuff_t *tvb, packet_info *pinfo, gint offset,
                guint8 flags, gboolean little_endian, int octets_to_next_header, proto_tree *tree,
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
  proto_item* octet_item;
  rtps_util_decode_flags(tree, tvb, offset + 1, flags, NOKEY_DATA_FRAG_FLAGS);

  octet_item = proto_tree_add_item(tree, hf_rtps_sm_octets_to_next_header, tvb,
                        offset + 2, 2, little_endian ? ENC_LITTLE_ENDIAN : ENC_BIG_ENDIAN);

  /* Calculates the minimum length for this submessage */
  min_len = 28;
  if ((flags & FLAG_NOKEY_DATA_Q) != 0) min_len += 4;

  if (octets_to_next_header < min_len) {
    expert_add_info_format(pinfo, octet_item, &ei_rtps_sm_octets_to_next_header_error, "(Error: should be >= %u)", min_len);
    return;
  }

  /* Skip decoding the entire packet if (tree == NULL) */
  if (tree == NULL) {
    return;
  }

  offset += 4;

  /* readerEntityId */
  rtps_util_add_entity_id(tree, tvb, offset, hf_rtps_sm_rdentity_id, hf_rtps_sm_rdentity_id_key,
                        hf_rtps_sm_rdentity_id_kind, ett_rtps_rdentity, "readerEntityId", NULL);
  offset += 4;

  /* writerEntityId */
  rtps_util_add_entity_id(tree, tvb, offset, hf_rtps_sm_wrentity_id, hf_rtps_sm_wrentity_id_key,
                        hf_rtps_sm_wrentity_id_kind, ett_rtps_wrentity, "writerEntityId", NULL);
  offset += 4;

  /* Sequence number */
  rtps_util_add_seq_number(tree, tvb, offset, little_endian, "writerSeqNumber");
  offset += 8;

  /* Fragment number */
  proto_tree_add_item(tree, hf_rtps_nokey_data_frag_number, tvb,
                        offset, 4, little_endian ? ENC_LITTLE_ENDIAN : ENC_BIG_ENDIAN);
  offset += 4;

  /* Fragments in submessage */
  proto_tree_add_item(tree, hf_rtps_nokey_data_frag_num_fragments, tvb,
                        offset, 2, little_endian ? ENC_LITTLE_ENDIAN : ENC_BIG_ENDIAN);
  offset += 2;

  /* Fragment size */
  proto_tree_add_item(tree, hf_rtps_nokey_data_frag_size, tvb,
                        offset, 2, little_endian ? ENC_LITTLE_ENDIAN : ENC_BIG_ENDIAN);
  offset += 2;

  /* InlineQos */
  if ((flags & FLAG_DATA_Q_v2) != 0) {
    offset = dissect_parameter_sequence(tree, pinfo, tvb, offset, little_endian,
                        octets_to_next_header - (offset - old_offset) + 4,
                        "inlineQos", 0x0200, NULL, vendor_id);
  }

  /* SerializedData */
  if ((flags & FLAG_DATA_D_v2) != 0) {
    dissect_serialized_data(tree, pinfo, tvb,offset,
                        octets_to_next_header - (offset - old_offset) + 4,
                        "serializedData", vendor_id);
  }
}


/* *********************************************************************** */
/* *                            A C K N A C K                            * */
/* *********************************************************************** */
static void dissect_ACKNACK(tvbuff_t *tvb, packet_info *pinfo, gint offset, guint8 flags,
                gboolean little_endian, int octets_to_next_header, proto_tree *tree, proto_item *item) {
  /* RTPS 1.0/1.1:
   * 0...2...........7...............15.............23...............31
   * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   * |   ACK         |X|X|X|X|X|X|F|E|      octetsToNextHeader       |
   * +---------------+---------------+---------------+---------------+
   * | ObjectId readerObjectId                                       |
   * +---------------+---------------+---------------+---------------+
   * | ObjectId writerObjectId                                       |
   * +---------------+---------------+---------------+---------------+
   * |                                                               |
   * + Bitmap bitmap                                                 +
   * |                                                               |
   * +---------------+---------------+---------------+---------------+
   * | Counter count                                                 |
   * +---------------+---------------+---------------+---------------+
   *
   * RTPS 1.2/2.0:
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
  proto_item* octet_item;

  rtps_util_decode_flags(tree, tvb, offset + 1, flags, ACKNACK_FLAGS);

  octet_item = proto_tree_add_item(tree,
                        hf_rtps_sm_octets_to_next_header,
                        tvb,
                        offset + 2,
                        2,
                        little_endian ? ENC_LITTLE_ENDIAN : ENC_BIG_ENDIAN);

  if (octets_to_next_header < 20) {
    expert_add_info_format(pinfo, octet_item, &ei_rtps_sm_octets_to_next_header_error, "(Error: should be >= 20)");
    return;
  }

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
    proto_tree_add_item(tree, hf_rtps_acknack_counter, tvb, offset, 4, little_endian ? ENC_LITTLE_ENDIAN : ENC_BIG_ENDIAN);
  } else if (offset < original_offset + octets_to_next_header) {
    /* In this case there must be something wrong in the bitmap: there
     * are some extra bytes that we don't know how to decode
     */
    expert_add_info_format(pinfo, item, &ei_rtps_extra_bytes, "Don't know how to decode those extra bytes: %d", octets_to_next_header - offset);
  } else if (offset > original_offset + octets_to_next_header) {
    /* Decoding the bitmap went over the end of this submessage.
     * Enter an item in the protocol tree that spans over the entire
     * submessage.
     */
    expert_add_info(pinfo, item, &ei_rtps_missing_bytes);
  }

}

/* *********************************************************************** */
/* *                          N A C K _ F R A G                          * */
/* *********************************************************************** */
static void dissect_NACK_FRAG(tvbuff_t *tvb, packet_info *pinfo, gint offset, guint8 flags,
                              gboolean little_endian, int octets_to_next_header, proto_tree *tree) {
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
  proto_item* octet_item;

  rtps_util_decode_flags(tree, tvb, offset + 1, flags, NACK_FRAG_FLAGS);

  octet_item = proto_tree_add_item(tree, hf_rtps_sm_octets_to_next_header, tvb,
                        offset + 2, 2, little_endian ? ENC_LITTLE_ENDIAN : ENC_BIG_ENDIAN);

  if (octets_to_next_header < 24) {
    expert_add_info_format(pinfo, octet_item, &ei_rtps_sm_octets_to_next_header_error, "(Error: should be >= 24)");
    return;
  }

  /* Skip decoding the entire packet if (tree == NULL)
   * Note that we still need to decode the statusInfo and the writer ID
   */
  if (tree == NULL) {
    return;
  }

  offset += 4;

  /* readerEntityId */
  rtps_util_add_entity_id(tree, tvb, offset, hf_rtps_sm_rdentity_id, hf_rtps_sm_rdentity_id_key,
                        hf_rtps_sm_rdentity_id_kind, ett_rtps_rdentity, "readerEntityId", NULL);
  offset += 4;

  /* writerEntityId */
  rtps_util_add_entity_id(tree, tvb, offset, hf_rtps_sm_wrentity_id, hf_rtps_sm_wrentity_id_key,
                        hf_rtps_sm_wrentity_id_kind, ett_rtps_wrentity, "writerEntityId", NULL);
  offset += 4;

  /* Writer sequence number */
  rtps_util_add_seq_number(tree, tvb, offset, little_endian, "writerSN");
  offset += 8;

  /* FragmentNumberSet */
  offset = rtps_util_add_fragment_number_set(tree, pinfo, tvb, offset, little_endian,
                        "fragmentNumberState", octets_to_next_header - 20);

  if (offset == -1) {
    return;
  }
  /* Count */
  proto_tree_add_item(tree, hf_rtps_nack_frag_count, tvb,
                        offset, 4, little_endian ? ENC_LITTLE_ENDIAN : ENC_BIG_ENDIAN);
}

/* *********************************************************************** */
/* *                           H E A R T B E A T                         * */
/* *********************************************************************** */
static void dissect_HEARTBEAT(tvbuff_t *tvb, packet_info *pinfo, gint offset, guint8 flags,
                gboolean little_endian, int octets_to_next_header, proto_tree *tree, guint16 version) {
  /* RTPS 1.0/1.1:
   * 0...2...........7...............15.............23...............31
   * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   * |   HEARTBEAT   |X|X|X|X|X|L|F|E|      octetsToNextHeader       |
   * +---------------+---------------+---------------+---------------+
   * | ObjectId readerObjectId                                       |
   * +---------------+---------------+---------------+---------------+
   * | ObjectId writerObjectId                                       |
   * +---------------+---------------+---------------+---------------+
   * |                                                               |
   * + SequenceNumber firstAvailableSeqNumber                        +
   * |                                                               |
   * +---------------+---------------+---------------+---------------+
   * |                                                               |
   * + SequenceNumber lastSeqNumber                                  +
   * |                                                               |
   * +---------------+---------------+---------------+---------------+
   * | long counter                                                  |
   * +---------------+---------------+---------------+---------------+
   *
   * Notes:
   *   - on RTPS 1.0, counter is not present
   *   - on RTPS 1.0, L flag is not present
   *
   * RTPS 1.2/2.0:
   * 0...2...........7...............15.............23...............31
   * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   * |   HEARTBEAT   |X|X|X|X|X|X|F|E|      octetsToNextHeader       |
   * +---------------+---------------+---------------+---------------+
   * | EntityId readerEntityId                                       |
   * +---------------+---------------+---------------+---------------+
   * | EntityId writerEntityId                                       |
   * +---------------+---------------+---------------+---------------+
   * |                                                               |
   * + SequenceNumber firstAvailableSeqNumber                        +
   * |                                                               |
   * +---------------+---------------+---------------+---------------+
   * |                                                               |
   * + SequenceNumber lastSeqNumber                                  +
   * |                                                               |
   * +---------------+---------------+---------------+---------------+
   * | Counter count                                                 |
   * +---------------+---------------+---------------+---------------+
   */
  guint32 counter;
  proto_item* octet_item;

  rtps_util_decode_flags(tree, tvb, offset + 1, flags, HEARTBEAT_FLAGS);

  octet_item = proto_tree_add_item(tree,
                        hf_rtps_sm_octets_to_next_header,
                        tvb,
                        offset + 2,
                        2,
                        little_endian ? ENC_LITTLE_ENDIAN : ENC_BIG_ENDIAN);

  if ((octets_to_next_header < 24) && (version <= 0x0101)) {
    expert_add_info_format(pinfo, octet_item, &ei_rtps_sm_octets_to_next_header_error, "(Error: should be >= 24)");
    return;
  }
  else if (octets_to_next_header < 28) {
    expert_add_info_format(pinfo, octet_item, &ei_rtps_sm_octets_to_next_header_error, "(Error: should be >= 28)");
    return;
  }

  offset += 4;

  /* readerEntityId */
  rtps_util_add_entity_id(tree, tvb, offset, hf_rtps_sm_rdentity_id, hf_rtps_sm_rdentity_id_key,
                        hf_rtps_sm_rdentity_id_kind, ett_rtps_rdentity, "readerEntityId", NULL);
  offset += 4;

  /* writerEntityId */
  rtps_util_add_entity_id(tree, tvb, offset, hf_rtps_sm_wrentity_id, hf_rtps_sm_wrentity_id_key,
                        hf_rtps_sm_wrentity_id_kind, ett_rtps_wrentity, "writerEntityId", NULL);
  offset += 4;

  /* First available Sequence Number */
  rtps_util_add_seq_number(tree, tvb, offset, little_endian, "firstAvailableSeqNumber");
  offset += 8;

  /* Last Sequence Number */
  rtps_util_add_seq_number(tree, tvb, offset, little_endian, "lastSeqNumber");
  offset += 8;

  /* Counter: it was not present in RTPS 1.0 */
  if (version >= 0x0101) {
    counter = NEXT_guint32(tvb, offset, little_endian);
    proto_tree_add_text(tree, tvb, offset, 4, "count: %u", counter);
  }
}

/* *********************************************************************** */
/* *                 H E A R T B E A T _ B A T C H                       * */
/* *********************************************************************** */
static void dissect_HEARTBEAT_BATCH(tvbuff_t *tvb, packet_info *pinfo, gint offset,
                guint8 flags, gboolean little_endian, int octets_to_next_header, proto_tree *tree) {
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
  proto_item* octet_item;

  rtps_util_decode_flags(tree, tvb, offset + 1, flags, HEARTBEAT_BATCH_FLAGS);

  octet_item = proto_tree_add_item(tree, hf_rtps_sm_octets_to_next_header, tvb,
                        offset + 2, 2, little_endian ? ENC_LITTLE_ENDIAN : ENC_BIG_ENDIAN);

  if (octets_to_next_header < 36) {
    expert_add_info_format(pinfo, octet_item, &ei_rtps_sm_octets_to_next_header_error, "(Error: should be >= 36)");
    return;
  }

  /* Skip decoding the entire packet if (tree == NULL) */
  if (tree == NULL) {
    return;
  }

  offset += 4;

  /* readerEntityId */
  rtps_util_add_entity_id(tree, tvb, offset, hf_rtps_sm_rdentity_id, hf_rtps_sm_rdentity_id_key,
                        hf_rtps_sm_rdentity_id_kind, ett_rtps_rdentity, "readerEntityId", NULL);
  offset += 4;

  /* writerEntityId */
  rtps_util_add_entity_id(tree, tvb, offset, hf_rtps_sm_wrentity_id, hf_rtps_sm_wrentity_id_key,
                        hf_rtps_sm_wrentity_id_kind, ett_rtps_wrentity, "writerEntityId", NULL);
  offset += 4;

  /* First available Batch Sequence Number */
  rtps_util_add_seq_number(tree, tvb, offset, little_endian, "firstBatchSN");
  offset += 8;

  /* Last Batch Sequence Number */
  rtps_util_add_seq_number(tree, tvb, offset, little_endian, "lastBatchSN");
  offset += 8;

  /* First available Sequence Number */
  rtps_util_add_seq_number(tree, tvb, offset, little_endian, "firstSeqNumber");
  offset += 8;

  /* Last Sequence Number */
  rtps_util_add_seq_number(tree, tvb, offset, little_endian, "lastSeqNumber");
  offset += 8;

  /* Counter */
  proto_tree_add_item(tree, hf_rtps_heartbeat_batch_count, tvb, offset,
                      4, little_endian ? ENC_LITTLE_ENDIAN : ENC_BIG_ENDIAN);
}

/* *********************************************************************** */
/* *                   H E A R T B E A T _ F R A G                       * */
/* *********************************************************************** */
static void dissect_HEARTBEAT_FRAG(tvbuff_t *tvb, packet_info *pinfo, gint offset, guint8 flags,
                gboolean little_endian, int octets_to_next_header, proto_tree *tree) {
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
  proto_item* octet_item;

  rtps_util_decode_flags(tree, tvb, offset + 1, flags, HEARTBEAT_FRAG_FLAGS);

  octet_item = proto_tree_add_item(tree, hf_rtps_sm_octets_to_next_header, tvb,
                        offset + 2, 2, little_endian ? ENC_LITTLE_ENDIAN : ENC_BIG_ENDIAN);

  if (octets_to_next_header < 24) {
    expert_add_info_format(pinfo, octet_item, &ei_rtps_sm_octets_to_next_header_error, "(Error: should be >= 24)");
    return;
  }

  /* Skip decoding the entire packet if (tree == NULL) */
  if (tree == NULL) {
    return;
  }

  offset += 4;

  /* readerEntityId */
  rtps_util_add_entity_id(tree, tvb, offset, hf_rtps_sm_rdentity_id, hf_rtps_sm_rdentity_id_key,
                        hf_rtps_sm_rdentity_id_kind, ett_rtps_rdentity, "readerEntityId", NULL);
  offset += 4;

  /* writerEntityId */
  rtps_util_add_entity_id(tree, tvb, offset, hf_rtps_sm_wrentity_id, hf_rtps_sm_wrentity_id_key,
                        hf_rtps_sm_wrentity_id_kind, ett_rtps_wrentity, "writerEntityId", NULL);
  offset += 4;

  /* First available Sequence Number */
  rtps_util_add_seq_number(tree, tvb, offset, little_endian, "writerSeqNumber");
  offset += 8;

  /* Fragment number */
  proto_tree_add_item(tree, hf_rtps_heartbeat_frag_number, tvb, offset,
                      4, little_endian ? ENC_LITTLE_ENDIAN : ENC_BIG_ENDIAN);
  offset += 4;

  /* Counter */
  proto_tree_add_item(tree, hf_rtps_heartbeat_frag_count, tvb, offset,
                      4, little_endian ? ENC_LITTLE_ENDIAN : ENC_BIG_ENDIAN);
}

/* *********************************************************************** */
/* *                     R T P S _ D A T A                               * */
/* *                           A N D                                     * */
/* *             R T P S _ D A T A _ S E S S I O N                       * */
/* *********************************************************************** */
static void dissect_RTPS_DATA(tvbuff_t *tvb, packet_info *pinfo, gint offset, guint8 flags,
                gboolean little_endian, int octets_to_next_header, proto_tree *tree,
                guint16 vendor_id, gboolean is_session) {
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
  proto_item* octet_item;

  rtps_util_decode_flags(tree, tvb, offset + 1, flags, RTPS_DATA_FLAGS);

  octet_item = proto_tree_add_item(tree, hf_rtps_sm_octets_to_next_header, tvb,
                        offset + 2, 2, little_endian ? ENC_LITTLE_ENDIAN : ENC_BIG_ENDIAN);

  /* Calculates the minimum length for this submessage */
  min_len = 24;
  if (is_session) {
    min_len += 8;
  }
  if ((flags & FLAG_RTPS_DATA_Q) != 0) min_len += 4;
  if ((flags & FLAG_RTPS_DATA_D) != 0) min_len += 4;
  if ((flags & FLAG_RTPS_DATA_K) != 0) min_len += 4;

  if (octets_to_next_header < min_len) {
    expert_add_info_format(pinfo, octet_item, &ei_rtps_sm_octets_to_next_header_error, "(Error: should be >= %u)", min_len);
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
      /*offset = */dissect_parameter_sequence(tree, pinfo, tvb, offset, little_endian,
                        octets_to_next_header - (offset - old_offset) + 4,
                        "inlineQos", 0x0200, &status_info, vendor_id);
    }
    info_summary_append_ex(pinfo, wid, status_info);
    return;
  }

  offset += 4;

  /* extraFlags */
  proto_tree_add_item(tree, hf_rtps_extra_flags, tvb, offset, 2, ENC_BIG_ENDIAN);
  offset += 2;

  /* octetsToInlineQos */
  proto_tree_add_text(tree, tvb, offset, 2, "Octets to inline QoS: %d",
                        NEXT_guint16(tvb, offset, little_endian));
  offset += 2;

  /* readerEntityId */
  rtps_util_add_entity_id(tree, tvb, offset, hf_rtps_sm_rdentity_id, hf_rtps_sm_rdentity_id_key,
                        hf_rtps_sm_rdentity_id_kind, ett_rtps_rdentity, "readerEntityId", NULL);
  offset += 4;

  /* writerEntityId */
  rtps_util_add_entity_id(tree, tvb, offset, hf_rtps_sm_wrentity_id, hf_rtps_sm_wrentity_id_key,
                        hf_rtps_sm_wrentity_id_kind, ett_rtps_wrentity, "writerEntityId", &wid);
  offset += 4;

  /* Sequence number */
  if (is_session) {
    rtps_util_add_seq_number(tree, tvb, offset, little_endian, "writerSessionSeqNumber");
    offset += 8;

    rtps_util_add_seq_number(tree, tvb, offset, little_endian, "writerVirtualSeqNumber");
    offset += 8;
  } else {
    rtps_util_add_seq_number(tree, tvb, offset, little_endian, "writerSeqNumber");
    offset += 8;
  }

  /* InlineQos */
  if ((flags & FLAG_RTPS_DATA_Q) != 0) {
    offset = dissect_parameter_sequence(tree, pinfo, tvb, offset, little_endian,
                        octets_to_next_header - (offset - old_offset) + 4,
                        "inlineQos", 0x0200, &status_info, vendor_id);
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
      proto_item * ti = proto_tree_add_text(tree, tvb, offset,
                        octets_to_next_header - (offset - old_offset) + 4,
                        "ParticipantMessageData");

      rtps_pm_tree = proto_item_add_subtree(ti, ett_rtps_part_message_data);
      /* Encapsulation ID */
      encapsulation_id =  NEXT_guint16(tvb, offset, FALSE);   /* Always big endian */

      proto_tree_add_text(rtps_pm_tree, tvb, offset, 2, "encapsulation kind: %s",
                        val_to_str(encapsulation_id, encapsulation_id_vals, "unknown (%02x)"));
      offset += 2;

#if 0 /* XXX: encapsulation_little_endian not actually used anywhere ?? */
      /* Sets the correct values for encapsulation_le */
      if (encapsulation_id == ENCAPSULATION_CDR_LE ||
          encapsulation_id == ENCAPSULATION_PL_CDR_LE) {
        encapsulation_little_endian = 1;
      }
#endif

      /* Encapsulation length (or option) */
      encapsulation_len =  NEXT_guint16(tvb, offset, FALSE);    /* Always big endian */
      proto_tree_add_text(rtps_pm_tree, tvb, offset, 2,
                        "encapsulation options: %04x", encapsulation_len);
      offset += 2;

      guid_tree = proto_item_add_subtree(ti, ett_rtps_part_message_data);

      rtps_util_add_guid_prefix_v2(guid_tree, tvb, offset, hf_rtps_sm_guid_prefix, hf_rtps_sm_host_id,
                        hf_rtps_sm_app_id, hf_rtps_sm_counter, "participantGuidPrefix");
      offset += 12;

      /* Kind */
      kind =  NEXT_guint32(tvb, offset, FALSE);   /* Always big endian */
      proto_tree_add_text(guid_tree, tvb, offset, 4, "kind: %s",
            val_to_str(kind, participant_message_data_kind, "unknown (%04x)"));
      offset += 4;

      rtps_util_add_seq_octets(rtps_pm_tree, pinfo, tvb, offset, little_endian,
                               octets_to_next_header - (offset - old_offset), hf_rtps_data_serialize_data);

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
      dissect_serialized_data(tree, pinfo, tvb, offset,
                        octets_to_next_header - (offset - old_offset) + 4,
                        label, vendor_id);
    }
  }

  info_summary_append_ex(pinfo, wid, status_info);
}

/* *********************************************************************** */
/* *                 R T P S _ D A T A _ F R A G                         * */
/* *********************************************************************** */
static void dissect_RTPS_DATA_FRAG(tvbuff_t *tvb,
                packet_info *pinfo,
                gint offset,
                guint8 flags,
                gboolean little_endian,
                int octets_to_next_header,
                proto_tree *tree,
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
  proto_item* octet_item;

  rtps_util_decode_flags(tree, tvb, offset + 1, flags, RTPS_DATA_FRAG_FLAGS);

  octet_item = proto_tree_add_item(tree, hf_rtps_sm_octets_to_next_header, tvb,
                        offset + 2, 2, little_endian ? ENC_LITTLE_ENDIAN : ENC_BIG_ENDIAN);

  /* Calculates the minimum length for this submessage */
  min_len = 36;
  if ((flags & FLAG_RTPS_DATA_FRAG_Q) != 0) min_len += 4;

  if (octets_to_next_header < min_len) {
    expert_add_info_format(pinfo, octet_item, &ei_rtps_sm_octets_to_next_header_error, "(Error: should be >= %u)", min_len);
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
      /*offset = */dissect_parameter_sequence(tree, pinfo, tvb, offset, little_endian,
                        octets_to_next_header - (offset - old_offset) + 4,
                        "inlineQos", 0x0200, &status_info, vendor_id);
    }
    info_summary_append_ex(pinfo, wid, status_info);
    return;
  }

  offset += 4;

  /* extraFlags */
  proto_tree_add_item(tree, hf_rtps_extra_flags, tvb, offset, 2, ENC_BIG_ENDIAN);
  offset += 2;

  /* octetsToInlineQos */
  proto_tree_add_text(tree, tvb, offset, 2, "Octets to inline QoS: %d",
                        NEXT_guint16(tvb, offset, little_endian));
  offset += 2;

  /* readerEntityId */
  rtps_util_add_entity_id(tree, tvb, offset, hf_rtps_sm_rdentity_id, hf_rtps_sm_rdentity_id_key,
                        hf_rtps_sm_rdentity_id_kind, ett_rtps_rdentity, "readerEntityId", NULL);
  offset += 4;

  /* writerEntityId */
  rtps_util_add_entity_id(tree, tvb, offset, hf_rtps_sm_wrentity_id, hf_rtps_sm_wrentity_id_key,
                        hf_rtps_sm_wrentity_id_kind, ett_rtps_wrentity, "writerEntityId", &wid);
  offset += 4;


  /* Sequence number */
  rtps_util_add_seq_number(tree, tvb, offset, little_endian, "writerSeqNumber");
  offset += 8;

  /* Fragment number */
  proto_tree_add_item(tree, hf_rtps_data_frag_number, tvb,
                        offset, 4, little_endian ? ENC_LITTLE_ENDIAN : ENC_BIG_ENDIAN);
  offset += 4;

  /* Fragments in submessage */
  proto_tree_add_item(tree, hf_rtps_data_frag_num_fragments, tvb,
                        offset, 2, little_endian ? ENC_LITTLE_ENDIAN : ENC_BIG_ENDIAN);
  offset += 2;

  /* Fragment size */
  proto_tree_add_item(tree, hf_rtps_data_frag_size, tvb,
                        offset, 2, little_endian ? ENC_LITTLE_ENDIAN : ENC_BIG_ENDIAN);
  offset += 2;

  /* sampleSize */
  proto_tree_add_item(tree, hf_rtps_data_frag_sample_size, tvb,
                        offset, 4, little_endian ? ENC_LITTLE_ENDIAN : ENC_BIG_ENDIAN);
  offset += 4;

  /* InlineQos */
  if ((flags & FLAG_RTPS_DATA_FRAG_Q) != 0) {
    offset = dissect_parameter_sequence(tree, pinfo, tvb, offset, little_endian,
                        octets_to_next_header - (offset - old_offset) + 4,
                        "inlineQos", 0x0200, &status_info, vendor_id);
  }

  /* SerializedData */
  {
    const char *label = "serializedData";
    if ((flags & FLAG_RTPS_DATA_FRAG_K) != 0) {
      label = "serializedKey";
    }
    dissect_serialized_data(tree, pinfo, tvb, offset,
                        octets_to_next_header - (offset - old_offset) + 4,
                        label, vendor_id);
  }
  info_summary_append_ex(pinfo, wid, status_info);
}

/* *********************************************************************** */
/* *                 R T P S _ D A T A _ B A T C H                       * */
/* *********************************************************************** */
static void dissect_RTPS_DATA_BATCH(tvbuff_t *tvb, packet_info *pinfo, gint offset,
                guint8 flags, gboolean little_endian, int octets_to_next_header,
                proto_tree *tree, guint16 vendor_id) {
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
  gint32 sampleListOffset;
  guint16 encapsulation_id;
  guint16 *sample_info_flags = NULL;
  guint32 *sample_info_length = NULL;
  gint32  sample_info_count = 0,
          sample_info_max = rtps_max_batch_samples_dissected;
  proto_item* octet_item;

  rtps_util_decode_flags(tree, tvb, offset + 1, flags, RTPS_DATA_BATCH_FLAGS);

  octet_item = proto_tree_add_item(tree, hf_rtps_sm_octets_to_next_header, tvb,
                        offset + 2, 2, little_endian ? ENC_LITTLE_ENDIAN : ENC_BIG_ENDIAN);

  /* Calculates the minimum length for this submessage */
  min_len = 44;
  if ((flags & FLAG_RTPS_DATA_BATCH_Q) != 0) min_len += 4;

  if (octets_to_next_header < min_len) {
    expert_add_info_format(pinfo, octet_item, &ei_rtps_sm_octets_to_next_header_error, "(Error: should be >= %u)", min_len);
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
    if ((flags & FLAG_DATA_Q_v2) != 0) {
      /*offset = */dissect_parameter_sequence(tree, pinfo, tvb, offset,
                        little_endian, octets_to_next_header - (offset - old_offset) + 4,
                        "inlineQos", 0x0200, &status_info, vendor_id);
    }
    info_summary_append_ex(pinfo, wid, status_info);
    return;
  }

  offset += 4;

  /* extraFlags */
  proto_tree_add_item(tree, hf_rtps_extra_flags, tvb, offset, 2, ENC_BIG_ENDIAN);
  offset += 2;

  /* octetsToInlineQos */
  proto_tree_add_text(tree, tvb, offset, 2, "Octets to inline QoS: %d",
                        NEXT_guint16(tvb, offset, little_endian));
  offset += 2;


  /* readerEntityId */
  rtps_util_add_entity_id(tree, tvb, offset, hf_rtps_sm_rdentity_id, hf_rtps_sm_rdentity_id_key,
                        hf_rtps_sm_rdentity_id_kind, ett_rtps_rdentity, "readerEntityId", NULL);
  offset += 4;

  /* writerEntityId */
  rtps_util_add_entity_id(tree, tvb, offset, hf_rtps_sm_wrentity_id, hf_rtps_sm_wrentity_id_key,
                        hf_rtps_sm_wrentity_id_kind, ett_rtps_wrentity, "writerEntityId", &wid);
  offset += 4;


  /* Batch sequence number */
  rtps_util_add_seq_number(tree, tvb, offset, little_endian, "batchSeqNumber");
  offset += 8;

  /* First stample sequence number */
  rtps_util_add_seq_number(tree, tvb, offset, little_endian, "firstSampleSeqNumber");
  offset += 8;

  /* offsetToLastSampleSN */
  proto_tree_add_item(tree, hf_rtps_data_batch_offset_to_last_sample_sn, tvb,
                        offset, 4, little_endian ? ENC_LITTLE_ENDIAN : ENC_BIG_ENDIAN);
  offset += 4;

  /* batchSampleCount */
  proto_tree_add_item(tree, hf_rtps_data_batch_sample_count, tvb,
                        offset, 4, little_endian ? ENC_LITTLE_ENDIAN : ENC_BIG_ENDIAN);
  offset += 4;

  /* Parameter list (if Q==1) */
  /* InlineQos */
  if ((flags & FLAG_RTPS_DATA_BATCH_Q) != 0) {
    offset = dissect_parameter_sequence(tree, pinfo, tvb, offset, little_endian,
                        octets_to_next_header - (offset - old_offset) + 4,
                        "batchInlineQos", 0x0200, &status_info, vendor_id);
  }

  /* octetsToSLEncapsulationId */
  octectsToSLEncapsulationId = NEXT_guint32(tvb, offset, little_endian);
  proto_tree_add_item(tree, hf_rtps_data_batch_octets_to_sl_encap_id, tvb,
                        offset, 4, octectsToSLEncapsulationId);
  offset += 4;
  sampleListOffset = offset + octectsToSLEncapsulationId;


  /* Sample info list */
  {
    proto_item *ti, *list_item;
    proto_tree *sil_tree;
    sample_info_count = 0;

    list_item = proto_tree_add_text(tree, tvb, offset, -1, "Sample Info List");
    sil_tree = proto_item_add_subtree(list_item, ett_rtps_sample_info_list);

    /* Allocate sample_info_flags and sample_info_length
     * to store a copy of the flags for each sample info */
    if (rtps_max_batch_samples_dissected == 0) {
      sample_info_max = 1024;   /* Max size of sampleInfo shown */
    }
    sample_info_flags = (guint16 *)wmem_alloc(wmem_packet_scope(), sizeof(guint16) * sample_info_max);
    sample_info_length = (guint32 *)wmem_alloc(wmem_packet_scope(), sizeof(guint32) * sample_info_max);

    /* Sample Info List: start decoding the sample info list until the offset
     * is greater or equal than 'sampleListOffset' */
    while (offset < sampleListOffset) {
      guint16 flags2;
      /*guint16 octetsToInlineQos;*/
      gint min_length;
      proto_tree * si_tree;
      gint offset_begin_sampleinfo = offset;

      if (rtps_max_batch_samples_dissected > 0 && (guint)sample_info_count >= rtps_max_batch_samples_dissected) {
        expert_add_info(pinfo, list_item, &ei_rtps_more_samples_available);
        offset = sampleListOffset;
        break;
      }

      ti = proto_tree_add_text(sil_tree, tvb, offset, -1, "sampleInfo[%d]", sample_info_count);
      si_tree = proto_item_add_subtree(ti, ett_rtps_sample_info);

      flags2 = NEXT_guint16(tvb, offset, FALSE); /* Flags are always big endian */
      sample_info_flags[sample_info_count] = flags2;
      rtps_util_decode_flags_16bit(si_tree, tvb, offset, flags2, RTPS_SAMPLE_INFO_FLAGS16);
      offset += 2;
      proto_tree_add_item(tree, hf_rtps_data_batch_octets_to_inline_qos, tvb,
                        offset, 2, little_endian ? ENC_LITTLE_ENDIAN : ENC_BIG_ENDIAN);
      offset += 2;

      min_length = 4;
      if ((flags2 & FLAG_SAMPLE_INFO_T) != 0) min_len += 8;
      if ((flags2 & FLAG_SAMPLE_INFO_Q) != 0) min_len += 4;
      if ((flags2 & FLAG_SAMPLE_INFO_O) != 0) min_len += 4;

      /* Ensure there are enough bytes to decode */
      if (sampleListOffset - offset < min_length) {
        expert_add_info_format(pinfo, ti, &ei_rtps_parameter_value_invalid, "Error: not enough bytes to dissect sample info");
        return;
      }

      /* Serialized data length */
      sample_info_length[sample_info_count] = NEXT_guint32(tvb, offset, little_endian);
      proto_tree_add_item(tree, hf_rtps_data_batch_serialized_data_length, tvb,
                        offset, 4, sample_info_length[sample_info_count]);
      offset += 4;

      /* Timestamp [only if T==1] */
      if ((flags2 & FLAG_SAMPLE_INFO_T) != 0) {
        rtps_util_add_ntp_time(si_tree, tvb, offset, little_endian, hf_rtps_data_batch_timestamp);
        offset += 8;
      }

      /* Offset SN [only if O==1] */
      if ((flags2 & FLAG_SAMPLE_INFO_O) != 0) {
        proto_tree_add_item(tree, hf_rtps_data_batch_offset_sn, tvb,
                        offset, 4, little_endian ? ENC_LITTLE_ENDIAN : ENC_BIG_ENDIAN);
        offset += 4;
      }

      /* Parameter list [only if Q==1] */
      if ((flags2 & FLAG_SAMPLE_INFO_Q) != 0) {
        offset = dissect_parameter_sequence(si_tree, pinfo, tvb, offset, little_endian,
                        octets_to_next_header - (offset - old_offset) + 4,
                        "sampleInlineQos", 0x0200, &status_info, vendor_id);
      }
      proto_item_set_len(ti, offset - offset_begin_sampleinfo);
      sample_info_count++;
    } /*   while (offset < sampleListOffset) */
  }

  /* Encapsulation ID for the entire data sequence */
  encapsulation_id =  NEXT_guint16(tvb, offset, FALSE);   /* Always big endian */
  proto_tree_add_text(tree, tvb, offset, 2,
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

    ti = proto_tree_add_text(tree, tvb, offset, -1, "Serialized Sample List");
    sil_tree = proto_item_add_subtree(ti, ett_rtps_sample_batch_list);
    for (count = 0; count < sample_info_count; ++count) {
      /* Ensure there are enough bytes in the buffer to dissect the next sample */
      if (octets_to_next_header - (offset - old_offset) + 4 < (gint)sample_info_length[count]) {
        expert_add_info_format(pinfo, ti, &ei_rtps_parameter_value_invalid, "Error: not enough bytes to dissect sample");
        return;
      }

      if ((sample_info_flags[count] & FLAG_SAMPLE_INFO_K) != 0) {
        label = "serializedKey[%d]";
      } else {
        label = "serializedData[%d]";
      }
      proto_tree_add_text(sil_tree, tvb, offset, sample_info_length[count], label, count);
      offset += sample_info_length[count];
    }
  }
  info_summary_append_ex(pinfo, wid, status_info);
}

/* *********************************************************************** */
/* *                                 G A P                               * */
/* *********************************************************************** */
static void dissect_GAP(tvbuff_t *tvb,
                packet_info *pinfo,
                gint offset,
                guint8 flags,
                gboolean little_endian,
                int octets_to_next_header,
                proto_tree *tree) {
  /* RTPS 1.0/1.1:
   * 0...2...........7...............15.............23...............31
   * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   * |   GAP         |X|X|X|X|X|X|X|E|      octetsToNextHeader       |
   * +---------------+---------------+---------------+---------------+
   * | ObjectId readerObjectId                                       |
   * +---------------+---------------+---------------+---------------+
   * | ObjectId writerObjectId                                       |
   * +---------------+---------------+---------------+---------------+
   * |                                                               |
   * + SequenceNumber firstSeqNumber                                 +
   * |                                                               |
   * +---------------+---------------+---------------+---------------+
   * |                                                               |
   * + Bitmap bitmap                                                 +
   * |                                                               |
   * +---------------+---------------+---------------+---------------+
   *
   * RTPS 1.2/2.0
   * 0...2...........7...............15.............23...............31
   * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   * |   GAP         |X|X|X|X|X|X|F|E|      octetsToNextHeader       |
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
  proto_item* octet_item;

  rtps_util_decode_flags(tree, tvb, offset + 1, flags, GAP_FLAGS);

  octet_item = proto_tree_add_item(tree, hf_rtps_sm_octets_to_next_header, tvb,
                        offset + 2, 2, little_endian ? ENC_LITTLE_ENDIAN : ENC_BIG_ENDIAN);

  if (octets_to_next_header < 24) {
    expert_add_info_format(pinfo, octet_item, &ei_rtps_sm_octets_to_next_header_error, "(Error: should be >= 24)");
    return;
  }

  offset += 4;

  /* readerEntityId */
  rtps_util_add_entity_id(tree, tvb, offset,
                        hf_rtps_sm_rdentity_id, hf_rtps_sm_rdentity_id_key, hf_rtps_sm_rdentity_id_kind,
                        ett_rtps_rdentity, "readerEntityId", NULL);
  offset += 4;

  /* writerEntityId */
  rtps_util_add_entity_id(tree, tvb, offset,
                        hf_rtps_sm_wrentity_id, hf_rtps_sm_wrentity_id_key, hf_rtps_sm_wrentity_id_kind,
                        ett_rtps_wrentity, "writerEntityId", NULL);
  offset += 4;


 /* First Sequence Number */
  rtps_util_add_seq_number(tree, tvb, offset, little_endian, "gapStart");
  offset += 8;

  /* Bitmap */
  rtps_util_add_bitmap(tree, tvb, offset, little_endian, "gapList");
}


/* *********************************************************************** */
/* *                           I N F O _ T S                             * */
/* *********************************************************************** */
void dissect_INFO_TS(tvbuff_t *tvb, packet_info *pinfo, gint offset, guint8 flags,
                gboolean little_endian, int octets_to_next_header, proto_tree *tree) {
  /* RTPS 1.0/1.1:
   * 0...2...........7...............15.............23...............31
   * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   * |   INFO_TS     |X|X|X|X|X|X|I|E|      octetsToNextHeader       |
   * +---------------+---------------+---------------+---------------+
   * |                                                               |
   * + NtpTime ntpTimestamp [only if I==0]                           +
   * |                                                               |
   * +---------------+---------------+---------------+---------------+
   *
   * RTPS 1.2/2.0:
   * 0...2...........7...............15.............23...............31
   * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   * |   INFO_TS     |X|X|X|X|X|X|T|E|      octetsToNextHeader       |
   * +---------------+---------------+---------------+---------------+
   * |                                                               |
   * + Timestamp timestamp [only if T==1]                            +
   * |                                                               |
   * +---------------+---------------+---------------+---------------+
   */

  int min_len;
  proto_item* octet_item;

  rtps_util_decode_flags(tree, tvb, offset + 1, flags, INFO_TS_FLAGS);

  octet_item = proto_tree_add_item(tree,
                        hf_rtps_sm_octets_to_next_header,
                        tvb,
                        offset + 2,
                        2,
                        little_endian ? ENC_LITTLE_ENDIAN : ENC_BIG_ENDIAN);

  min_len = 0;
  if ((flags & FLAG_INFO_TS_T) == 0) min_len += 8;

  if (octets_to_next_header != min_len) {
    expert_add_info_format(pinfo, octet_item, &ei_rtps_sm_octets_to_next_header_error, "(Error: should be == %u)", min_len);
    return;
  }

  offset += 4;

  if ((flags & FLAG_INFO_TS_T) == 0) {
    rtps_util_add_ntp_time(tree,
                        tvb,
                        offset,
                        little_endian,
                        hf_rtps_info_ts_timestamp);
  }
}


/* *********************************************************************** */
/* *                           I N F O _ S R C                           * */
/* *********************************************************************** */
void dissect_INFO_SRC(tvbuff_t *tvb, packet_info *pinfo, gint offset, guint8 flags,
                gboolean little_endian, int octets_to_next_header, proto_tree *tree, guint16 rtps_version) {
  /* RTPS 1.0/1.1:
   * 0...2...........7...............15.............23...............31
   * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   * |   INFO_SRC    |X|X|X|X|X|X|X|E|      octetsToNextHeader       |
   * +---------------+---------------+---------------+---------------+
   * | IPAddress appIpAddress                                        |
   * +---------------+---------------+---------------+---------------+
   * | ProtocolVersion version       | VendorId vendor               |
   * +---------------+---------------+---------------+---------------+
   * | HostId hostId                                                 |
   * +---------------+---------------+---------------+---------------+
   * | AppId appId                                                   |
   * +---------------+---------------+---------------+---------------+
   *
   * RTPS 1.2/2.0:
   * 0...2...........7...............15.............23...............31
   * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   * |   INFO_SRC    |X|X|X|X|X|X|X|E|      octetsToNextHeader       |
   * +---------------+---------------+---------------+---------------+
   * | long unused                                                   |
   * +---------------+---------------+---------------+---------------+
   * | ProtocolVersion version       | VendorId vendor               |
   * +---------------+---------------+---------------+---------------+
   * |                                                               |
   * + GuidPrefix guidPrefix                                         +
   * |                                                               |
   * +---------------+---------------+---------------+---------------+
   */
  proto_item* octet_item;
  guint32 ip;
  guint16 version;

  rtps_util_decode_flags(tree, tvb, offset + 1, flags, INFO_SRC_FLAGS);

  octet_item = proto_tree_add_item(tree, hf_rtps_sm_octets_to_next_header, tvb,
                        offset + 2, 2, little_endian ? ENC_LITTLE_ENDIAN : ENC_BIG_ENDIAN);

  if (rtps_version < 0x0200) {
    if (octets_to_next_header != 16) {
      expert_add_info_format(pinfo, octet_item, &ei_rtps_sm_octets_to_next_header_error, "(Error: should be == 16)");
      return;
    }
  } else {
    if (octets_to_next_header != 20) {
      expert_add_info_format(pinfo, octet_item, &ei_rtps_sm_octets_to_next_header_error, "(Error: should be == 20)");
      return;
    }
  }

  offset += 4;

  ip = NEXT_guint32(tvb, offset, little_endian);

  /* Use version field to determine what to display */
  version = tvb_get_ntohs(tvb, offset+4);
  if (version < 0x102) {
    proto_tree_add_ipv4(tree, hf_rtps_info_src_ip, tvb, offset, 4, ip);
  } else {
    proto_tree_add_uint(tree, hf_rtps_info_src_unused, tvb, offset, 4, ip);
  }

  offset += 4;

  rtps_util_add_protocol_version(tree, tvb, offset);
  offset += 2;

  /* Vendor ID */
  rtps_util_add_vendor_id(NULL, tvb, offset);
  offset += 2;

  if (rtps_version < 0x0200) {
    rtps_util_add_guid_prefix_v1(tree, tvb, offset,
                        hf_rtps_sm_guid_prefix, hf_rtps_sm_host_id, hf_rtps_sm_app_id,
                        hf_rtps_sm_instance_id, hf_rtps_sm_app_kind,
                        NULL);   /* Use default 'guidPrefix' */
  } else {
      rtps_util_add_guid_prefix_v2(tree, tvb, offset, hf_rtps_guid_prefix,
                        hf_rtps_host_id, hf_rtps_app_id, hf_rtps_sm_counter, NULL);
  }
}


/* *********************************************************************** */
/* *                    I N F O _ R E P L Y _ I P 4                      * */
/* *********************************************************************** */
static void dissect_INFO_REPLY_IP4(tvbuff_t *tvb, packet_info *pinfo, gint offset, guint8 flags,
                gboolean little_endian, int octets_to_next_header, proto_tree *tree) {
  /* RTPS 1.0/1.1:
   * 0...2...........7...............15.............23...............31
   * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   * |  INFO_REPLY  |X|X|X|X|X|X|M|E|      octetsToNextHeader       |
   * +---------------+---------------+---------------+---------------+
   * | IPAddress unicastReplyIpAddress                               |
   * +---------------+---------------+---------------+---------------+
   * | Port unicastReplyPort                                         |
   * +---------------+---------------+---------------+---------------+
   * | IPAddress multicastReplyIpAddress [ only if M==1 ]            |
   * +---------------+---------------+---------------+---------------+
   * | Port multicastReplyPort [ only if M==1 ]                      |
   * +---------------+---------------+---------------+---------------+
   *
   * RTPS 1.2/2.0:
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
  proto_item* octet_item;

  rtps_util_decode_flags(tree, tvb, offset + 1, flags, INFO_REPLY_IP4_FLAGS);

  octet_item = proto_tree_add_item(tree,
                        hf_rtps_sm_octets_to_next_header,
                        tvb,
                        offset + 2,
                        2,
                        little_endian ? ENC_LITTLE_ENDIAN : ENC_BIG_ENDIAN);

  min_len = 8;
  if ((flags & FLAG_INFO_REPLY_IP4_M) != 0) min_len += 8;

  if (octets_to_next_header != min_len) {
    expert_add_info_format(pinfo, octet_item, &ei_rtps_sm_octets_to_next_header_error, "(Error: should be == %u)", min_len);
    return;
  }

  offset += 4;


  /* unicastReplyLocator */
  rtps_util_add_locator_udp_v4(tree, pinfo, tvb, offset,
                        "unicastReplyLocator", little_endian);

  offset += 8;

  /* multicastReplyLocator */
  if ((flags & FLAG_INFO_REPLY_IP4_M) != 0) {
    rtps_util_add_locator_udp_v4(tree, pinfo, tvb, offset,
                        "multicastReplyLocator", little_endian);
    /*offset += 8;*/
  }
}

/* *********************************************************************** */
/* *                           I N F O _ D S T                           * */
/* *********************************************************************** */
static void dissect_INFO_DST(tvbuff_t *tvb, packet_info *pinfo, gint offset, guint8 flags,
                gboolean little_endian, int octets_to_next_header, proto_tree *tree, guint16 version) {
  /* RTPS 1.0/1.1:
   * 0...2...........7...............15.............23...............31
   * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   * |   INFO_DST    |X|X|X|X|X|X|X|E|      octetsToNextHeader       |
   * +---------------+---------------+---------------+---------------+
   * | HostId hostId                                                 |
   * +---------------+---------------+---------------+---------------+
   * | AppId appId                                                   |
   * +---------------+---------------+---------------+---------------+
   *
   * RTPS 1.2/2.0:
   * 0...2...........7...............15.............23...............31
   * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   * |   INFO_DST    |X|X|X|X|X|X|X|E|      octetsToNextHeader       |
   * +---------------+---------------+---------------+---------------+
   * |                                                               |
   * + GuidPrefix guidPrefix                                         +
   * |                                                               |
   * +---------------+---------------+---------------+---------------+
   */
  proto_item* octet_item;

  rtps_util_decode_flags(tree, tvb, offset + 1, flags, INFO_DST_FLAGS);

  octet_item = proto_tree_add_item(tree, hf_rtps_sm_octets_to_next_header, tvb,
                        offset + 2, 2, little_endian ? ENC_LITTLE_ENDIAN : ENC_BIG_ENDIAN);

  if (version < 0x0200) {
    if (octets_to_next_header != 8) {
      expert_add_info_format(pinfo, octet_item, &ei_rtps_sm_octets_to_next_header_error, "(Error: should be == 8)");
      return;
    }
  } else {
      if (octets_to_next_header != 12) {
      expert_add_info_format(pinfo, octet_item, &ei_rtps_sm_octets_to_next_header_error, "(Error: should be == 12)");
      return;
    }
  }

  offset += 4;

  if (version < 0x0200) {
    rtps_util_add_guid_prefix_v1(tree, tvb, offset,
                        hf_rtps_sm_guid_prefix, hf_rtps_sm_host_id, hf_rtps_sm_app_id,
                        hf_rtps_sm_instance_id, hf_rtps_sm_app_kind,
                        NULL);
  } else {
      rtps_util_add_guid_prefix_v2(tree, tvb, offset, hf_rtps_guid_prefix,
                        hf_rtps_host_id, hf_rtps_app_id, hf_rtps_sm_counter, NULL);
  }
}



/* *********************************************************************** */
/* *                        I N F O _ R E P L Y                          * */
/* *********************************************************************** */
static void dissect_INFO_REPLY(tvbuff_t *tvb,
                packet_info *pinfo,
                gint offset,
                guint8 flags,
                gboolean little_endian,
                int octets_to_next_header,
                proto_tree *tree) {
  /* RTPS 1.0/1.1:
   *   INFO_REPLY is *NOT* the same thing as the old INFO_REPLY.
   *
   * RTPS 1.2/2.0:
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
  proto_item* octet_item;

  rtps_util_decode_flags(tree, tvb, offset + 1, flags, INFO_REPLY_FLAGS);

  octet_item = proto_tree_add_item(tree,
                        hf_rtps_sm_octets_to_next_header,
                        tvb,
                        offset + 2,
                        2,
                        little_endian ? ENC_LITTLE_ENDIAN : ENC_BIG_ENDIAN);

  min_len = 4;
  if ((flags & FLAG_INFO_REPLY_M) != 0) min_len += 4;

  if (octets_to_next_header < min_len) {
    expert_add_info_format(pinfo, octet_item, &ei_rtps_sm_octets_to_next_header_error, "(Error: should be >= %u)", min_len);
    return;
  }

  offset += 4;

  /* unicastReplyLocatorList */
  offset = rtps_util_add_locator_list(tree, pinfo, tvb, offset, "unicastReplyLocatorList", little_endian);

  /* multicastReplyLocatorList */
  if ((flags & FLAG_INFO_REPLY_M) != 0) {
    /*offset = */rtps_util_add_locator_list(tree, pinfo, tvb, offset, "multicastReplyLocatorList", little_endian);
  }
}

static gboolean dissect_rtps_submessage_v2(tvbuff_t *tvb, packet_info *pinfo, gint offset, guint8 flags,
                                           gboolean little_endian, guint8 submessageId, guint16 vendor_id, gint octets_to_next_header,
                                           proto_tree* rtps_submessage_tree, proto_item* submessage_item)
{
  switch (submessageId)
  {
    case SUBMESSAGE_DATA_FRAG:
      dissect_DATA_FRAG(tvb, pinfo, offset, flags, little_endian, octets_to_next_header, rtps_submessage_tree, vendor_id);
      break;

    case SUBMESSAGE_NOKEY_DATA_FRAG:
      dissect_NOKEY_DATA_FRAG(tvb, pinfo, offset, flags, little_endian, octets_to_next_header, rtps_submessage_tree, vendor_id);
      break;

    case SUBMESSAGE_NACK_FRAG:
      dissect_NACK_FRAG(tvb, pinfo, offset, flags, little_endian, octets_to_next_header, rtps_submessage_tree);
      break;

    case SUBMESSAGE_ACKNACK_SESSION:
    case SUBMESSAGE_ACKNACK_BATCH:
      dissect_ACKNACK(tvb, pinfo, offset, flags, little_endian, octets_to_next_header, rtps_submessage_tree, submessage_item);
      break;

    case SUBMESSAGE_HEARTBEAT_SESSION:
    case SUBMESSAGE_HEARTBEAT_BATCH:
      dissect_HEARTBEAT_BATCH(tvb, pinfo, offset, flags, little_endian, octets_to_next_header, rtps_submessage_tree);
      break;

    case SUBMESSAGE_HEARTBEAT_FRAG:
      dissect_HEARTBEAT_FRAG(tvb, pinfo, offset, flags, little_endian, octets_to_next_header, rtps_submessage_tree);
      break;

    case SUBMESSAGE_RTPS_DATA_SESSION:
    case SUBMESSAGE_RTPS_DATA:
      dissect_RTPS_DATA(tvb, pinfo, offset, flags, little_endian, octets_to_next_header, rtps_submessage_tree,
                        vendor_id, (submessageId == SUBMESSAGE_RTPS_DATA_SESSION));
      break;

    case SUBMESSAGE_RTPS_DATA_FRAG:
      dissect_RTPS_DATA_FRAG(tvb, pinfo, offset, flags, little_endian, octets_to_next_header,
                                rtps_submessage_tree, vendor_id);
      break;

    case SUBMESSAGE_RTPS_DATA_BATCH:
      dissect_RTPS_DATA_BATCH(tvb, pinfo, offset, flags, little_endian, octets_to_next_header,
                                rtps_submessage_tree, vendor_id);
      break;

    default:
      return FALSE;
  }

  return TRUE;
}

static gboolean dissect_rtps_submessage_v1(tvbuff_t *tvb, packet_info *pinfo, gint offset, guint8 flags, gboolean little_endian,
                                           guint8 submessageId, guint16 version, guint16 vendor_id, gint octets_to_next_header,
                                           proto_tree* rtps_submessage_tree, proto_item* submessage_item)
{
  switch (submessageId)
  {
    case SUBMESSAGE_PAD:
      dissect_PAD(tvb, pinfo, offset, flags, little_endian, octets_to_next_header, rtps_submessage_tree);
      break;

    case SUBMESSAGE_DATA:
      if (version < 0x0200) {
        dissect_DATA_v1(tvb, pinfo, offset, flags, little_endian, octets_to_next_header, rtps_submessage_tree);
      } else {
        dissect_DATA_v2(tvb, pinfo, offset, flags, little_endian, octets_to_next_header, rtps_submessage_tree, vendor_id);
      }
      break;

    case SUBMESSAGE_NOKEY_DATA:
      dissect_NOKEY_DATA(tvb, pinfo, offset, flags, little_endian, octets_to_next_header, rtps_submessage_tree,
                         version, vendor_id);
      break;

    case SUBMESSAGE_ACKNACK:
      dissect_ACKNACK(tvb, pinfo, offset, flags, little_endian, octets_to_next_header, rtps_submessage_tree, submessage_item);
      break;

    case SUBMESSAGE_HEARTBEAT:
      dissect_HEARTBEAT(tvb, pinfo, offset, flags, little_endian, octets_to_next_header, rtps_submessage_tree, version);
      break;

    case SUBMESSAGE_GAP:
      dissect_GAP(tvb, pinfo, offset, flags, little_endian, octets_to_next_header, rtps_submessage_tree);
      break;

    case SUBMESSAGE_INFO_TS:
      dissect_INFO_TS(tvb, pinfo, offset, flags, little_endian, octets_to_next_header, rtps_submessage_tree);
      break;

    case SUBMESSAGE_INFO_SRC:
      dissect_INFO_SRC(tvb, pinfo, offset, flags, little_endian, octets_to_next_header, rtps_submessage_tree, version);
      break;

    case SUBMESSAGE_INFO_REPLY_IP4:
      dissect_INFO_REPLY_IP4(tvb, pinfo, offset, flags, little_endian, octets_to_next_header, rtps_submessage_tree);
      break;

    case SUBMESSAGE_INFO_DST:
      dissect_INFO_DST(tvb, pinfo, offset, flags, little_endian, octets_to_next_header, rtps_submessage_tree, version);
      break;

    case SUBMESSAGE_INFO_REPLY:
      dissect_INFO_REPLY(tvb, pinfo, offset, flags, little_endian, octets_to_next_header, rtps_submessage_tree);
      break;

    default:
      return FALSE;
  }

  return TRUE;
}

/***************************************************************************/
/* The main packet dissector function
 */
static gboolean dissect_rtps(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, gint offset)
{
  proto_item   *ti;
  proto_tree   *rtps_tree, *rtps_submessage_tree;
  guint8       submessageId, flags, majorRev;
  guint16      version, vendor_id;
  gboolean     little_endian, is_ping;
  gint         next_submsg, octets_to_next_header;
  int          sub_hf;
  const value_string* sub_vals;

  /* Check 'RTPS' signature:
   * A header is invalid if it has less than 16 octets
   */
  if (!tvb_bytes_exist(tvb, offset, 16))
    return FALSE;
  if (tvb_get_ntohl(tvb, offset) != RTPS_MAGIC_NUMBER)
    return FALSE;
  /* Distinguish between RTPS 1.x and 2.x here */
  majorRev = tvb_get_guint8(tvb,offset+4);
  if ((majorRev != 1) && (majorRev != 2))
    return FALSE;

  col_set_str(pinfo->cinfo, COL_PROTOCOL, "RTPS");
  col_clear(pinfo->cinfo, COL_INFO);

  /* create display subtree for the protocol */
  ti = proto_tree_add_item(tree, proto_rtps, tvb, 0, -1, ENC_NA);
  rtps_tree = proto_item_add_subtree(ti, ett_rtps);

  /*  Protocol Version */
  version = rtps_util_add_protocol_version(rtps_tree, tvb, offset+4);

  /*  Vendor Id  */
  vendor_id = rtps_util_add_vendor_id(rtps_tree, tvb, offset+6);

  is_ping = rtps_is_ping(tvb, pinfo, offset+8);

  if (!is_ping) {
    if (version < 0x0200)
      rtps_util_add_guid_prefix_v1(rtps_tree, tvb, offset+8,
                        hf_rtps_guid_prefix, hf_rtps_host_id, hf_rtps_app_id,
                        hf_rtps_app_id_instance_id, hf_rtps_app_id_app_kind, NULL);
    else
      rtps_util_add_guid_prefix_v2(rtps_tree, tvb, offset+8, hf_rtps_guid_prefix,
                        hf_rtps_host_id, hf_rtps_app_id, hf_rtps_sm_counter, NULL);

#ifdef RTI_BUILD
    pinfo->guid_prefix_host = tvb_get_ntohl(tvb, offset + 8);
    pinfo->guid_prefix_app  = tvb_get_ntohl(tvb, offset + 12);
    pinfo->guid_prefix_count = tvb_get_ntohl(tvb, offset + 16);
    pinfo->guid_rtps2 = 1;
#endif
  }

  /* Extract the domain id and participant index */
  {
    int domain_id, doffset, participant_idx = 0, nature;
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
    if (version < 0x0200) {
      domain_id = ((pinfo->destport - PORT_BASE)/10) % 100;
      participant_idx = (pinfo->destport - PORT_BASE) / 1000;
      nature    = (pinfo->destport % 10);
    } else {
      domain_id = (pinfo->destport - PORT_BASE) / 250;
      doffset = (pinfo->destport - PORT_BASE - domain_id * 250);
      if (doffset == 0) {
        nature = PORT_METATRAFFIC_MULTICAST;
      } else if (doffset == 1) {
        nature = PORT_USERTRAFFIC_MULTICAST;
      } else {
        participant_idx = (doffset - 10) / 2;
        if ( (doffset - 10) % 2 == 0) {
          nature = PORT_METATRAFFIC_UNICAST;
        } else {
          nature = PORT_USERTRAFFIC_UNICAST;
        }
      }
    }

    if ((nature == PORT_METATRAFFIC_UNICAST) || (nature == PORT_USERTRAFFIC_UNICAST) ||
        (version < 0x0200)) {
      ti = proto_tree_add_text(rtps_tree, tvb, 0, 0,
                        "Default port mapping: domainId=%d, "
                        "participantIdx=%d, nature=%s",
                        domain_id,
                        participant_idx,
                        val_to_str(nature, nature_type_vals, "%02x"));
    } else {
      ti = proto_tree_add_text(rtps_tree, tvb, 0, 0,
                        "Default port mapping: %s, domainId=%d",
                        val_to_str(nature, nature_type_vals, "%02x"),
                        domain_id);
    }

    mapping_tree = proto_item_add_subtree(ti, ett_rtps_default_mapping);
    ti = proto_tree_add_uint(mapping_tree, hf_rtps_domain_id, tvb, 0, 0, domain_id);
    PROTO_ITEM_SET_GENERATED(ti);
    if ((nature == PORT_METATRAFFIC_UNICAST) || (nature == PORT_USERTRAFFIC_UNICAST) ||
        (version < 0x0200)) {
      ti = proto_tree_add_uint(mapping_tree, hf_rtps_participant_idx, tvb, 0, 0, participant_idx);
      PROTO_ITEM_SET_GENERATED(ti);
    }
    ti = proto_tree_add_uint(mapping_tree, hf_rtps_nature_type, tvb, 0, 0, nature);
    PROTO_ITEM_SET_GENERATED(ti);
  }

  /* offset behind RTPS's Header (need to be set in case tree=NULL)*/
  offset += ((version < 0x0200) ? 16 : 20);

  while (tvb_reported_length_remaining(tvb, offset) > 0) {
    submessageId = tvb_get_guint8(tvb, offset);

    if (version < 0x0200) {
      sub_hf = hf_rtps_sm_id;
      sub_vals = submessage_id_vals;
    } else {
      sub_hf = hf_rtps_sm_idv2;
      sub_vals = submessage_id_valsv2;
    }

    col_append_sep_str(pinfo->cinfo, COL_INFO, ", ", val_to_str(submessageId, sub_vals, "Unknown[%02x]"));

    /* Creates the subtree 'Submessage: XXXX' */
    if (submessageId & 0x80) {
      ti = proto_tree_add_uint_format_value(rtps_tree, sub_hf, tvb, offset, 1,
                              submessageId, "Vendor-specific (0x%02x)", submessageId);
    } else {
      ti = proto_tree_add_uint(rtps_tree, sub_hf, tvb, offset, 1, submessageId);
    }

    rtps_submessage_tree = proto_item_add_subtree(ti, ett_rtps_submessage);

    /* Gets the flags */
    flags = tvb_get_guint8(tvb, offset + 1);

    /* Gets the E (Little endian) flag */
    little_endian = ((flags & FLAG_E) != 0);

    /* Octect-to-next-header */
    octets_to_next_header = NEXT_guint16(tvb, offset + 2, little_endian);
    if ((octets_to_next_header == 0) && (version >= 0x0200))
      octets_to_next_header = tvb_reported_length_remaining(tvb, offset + 4);
    next_submsg = offset + octets_to_next_header + 4;

    /* Set length of this item */
    proto_item_set_len(ti, octets_to_next_header + 4);

    /* Now decode each single submessage
     * The offset passed to the dissectors points to the start of the
     * submessage (at the ID byte).
     */
    if (!dissect_rtps_submessage_v1(tvb, pinfo, offset, flags, little_endian,
                                    submessageId, version, vendor_id,
                                    octets_to_next_header, rtps_submessage_tree, ti)) {
      if ((version < 0x0200) ||
          !dissect_rtps_submessage_v2(tvb, pinfo, offset, flags, little_endian, submessageId,
                                      vendor_id, octets_to_next_header, rtps_submessage_tree, ti)) {
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

  /* If TCP there's an extra OOB byte at the end of the message */
  /* TODO: What to do with it? */
  return TRUE;

}  /* dissect_rtps(...) */

static gboolean dissect_rtps_udp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
  gint offset = 0;

  return dissect_rtps(tvb, pinfo, tree, offset);
}

static gboolean dissect_rtps_tcp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
  /* In RTPS over TCP the first 4 bytes are the packet length
   * as 32-bit unsigned int coded as BIG ENDIAN
   * guint32 tcp_len  = tvb_get_ntohl(tvb, offset);
   */
  gint offset = 4;

  return dissect_rtps(tvb, pinfo, tree, offset);
}

void proto_register_rtps(void) {

  static hf_register_info hf[] = {

    /* Protocol Version (composed as major.minor) -------------------------- */
    { &hf_rtps_protocol_version, {
        "version",
        "rtps.version",
        FT_UINT16,
        BASE_HEX,
        NULL,
        0,
        "RTPS protocol version number",
        HFILL }
    },
    { &hf_rtps_protocol_version_major, {
        "major",
        "rtps.version.major",
        FT_INT8,
        BASE_DEC,
        NULL,
        0,
        "RTPS major protocol version number",
        HFILL }
    },
    { &hf_rtps_protocol_version_minor, {
        "minor",
        "rtps.version.minor",
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
        "rtps.domain_id",
        FT_UINT32,
        BASE_DEC,
        NULL,
        0,
        "Domain ID",
        HFILL }
    },

    { &hf_rtps_participant_idx, {
        "participant_idx",
        "rtps.participant_idx",
        FT_UINT32,
        BASE_DEC,
        NULL,
        0,
        "Participant index",
        HFILL }
    },
    { &hf_rtps_nature_type, {
        "traffic_nature",
        "rtps.traffic_nature",
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
        "rtps.vendorId",
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
        "rtps.guidPrefix",
        FT_UINT64,
        BASE_HEX,
        NULL,
        0,
        "GuidPrefix of the RTPS packet",
        HFILL }
    },

    /* Host ID ------------------------------------------------------------- */
    { &hf_rtps_host_id, {               /* HIDDEN */
        "hostId",
        "rtps.hostId",
        FT_UINT32,
        BASE_HEX,
        NULL,
        0,
        "Sub-component 'hostId' of the GuidPrefix of the RTPS packet",
        HFILL }
    },

    /* AppID (composed as instanceId, appKind) ----------------------------- */
    { &hf_rtps_app_id, {
        "appId",
        "rtps.appId",
        FT_UINT32,
        BASE_HEX,
        NULL,
        0,
        "Sub-component 'appId' of the GuidPrefix of the RTPS packet",
        HFILL }
    },
    { &hf_rtps_app_id_instance_id, {
        "appId.instanceId",
        "rtps.appId.instanceId",
        FT_UINT24,
        BASE_HEX,
        NULL,
        0,
        "'instanceId' field of the 'AppId' structure",
        HFILL }
    },
    { &hf_rtps_app_id_app_kind, {
        "appid.appKind",
        "rtps.appId.appKind",
        FT_UINT8,
        BASE_HEX,
        VALS(app_kind_vals),
        0,
        "'appKind' field of the 'AppId' structure",
        HFILL }
    },



    /* Submessage ID ------------------------------------------------------- */
    { &hf_rtps_sm_id, {
        "submessageId",
        "rtps.sm.id",
        FT_UINT8,
        BASE_HEX,
        VALS(submessage_id_vals),
        0,
        "defines the type of submessage",
        HFILL }
    },

    { &hf_rtps_sm_idv2, {
        "submessageId",
        "rtps.sm.id",
        FT_UINT8,
        BASE_HEX,
        VALS(submessage_id_valsv2),
        0,
        "defines the type of submessage",
        HFILL }
    },

    /* Submessage flags ---------------------------------------------------- */
    { &hf_rtps_sm_flags, {
        "Flags",
        "rtps.sm.flags",
        FT_UINT8,
        BASE_HEX,
        NULL,
        0,
        "bitmask representing the flags associated with a submessage",
        HFILL }
    },

    /* Octects to next header ---------------------------------------------- */
    { &hf_rtps_sm_octets_to_next_header, {
        "octetsToNextHeader",
        "rtps.sm.octetsToNextHeader",
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
        "rtps.sm.guidPrefix",
        FT_UINT64,
        BASE_HEX,
        NULL,
        0,
        "a generic guidPrefix that is transmitted inside the submessage (this is NOT the guidPrefix described in the packet header",
        HFILL }
    },

    { &hf_rtps_sm_host_id, {
        "host_id",
        "rtps.sm.guidPrefix.hostId",
        FT_UINT32,
        BASE_HEX,
        NULL,
        0,
        "The hostId component of the rtps.sm.guidPrefix",
        HFILL }
    },

    { &hf_rtps_sm_app_id, {
        "appId",
        "rtps.sm.guidPrefix.appId",
        FT_UINT32,
        BASE_HEX,
        NULL,
        0,
        "AppId component of the rtps.sm.guidPrefix",
        HFILL }
    },
    { &hf_rtps_sm_instance_id, {
        "instanceId",
        "rtps.sm.guidPrefix.appId.instanceId",
        FT_UINT24,
        BASE_HEX,
        NULL,
        0,
        "instanceId component of the AppId of the rtps.sm.guidPrefix",
        HFILL }
    },
    { &hf_rtps_sm_app_kind, {
        "appKind",
        "rtps.sm.guidPrefix.appId.appKind",
        FT_UINT8,
        BASE_HEX,
        NULL,
        0,
        "appKind component of the AppId of the rtps.sm.guidPrefix",
        HFILL }
    },
    { &hf_rtps_sm_counter, {
        "counter",
        "rtps.sm.guidPrefix.counter",
        FT_UINT32,
        BASE_HEX,
        NULL,
        0,
        "The counter component of the rtps.sm.guidPrefix",
        HFILL }
    },

    /* Entity ID (composed as entityKey, entityKind) ----------------------- */
    { &hf_rtps_sm_entity_id, {
        "entityId",
        "rtps.sm.entityId",
        FT_UINT32,
        BASE_HEX,
        VALS(entity_id_vals),
        0,
        "Object entity ID as it appears in a DATA submessage (keyHashSuffix)",
        HFILL }
    },
    { &hf_rtps_sm_entity_id_key, {
        "entityKey",
        "rtps.sm.entityId.entityKey",
        FT_UINT24,
        BASE_HEX,
        NULL,
        0,
        "'entityKey' field of the object entity ID",
        HFILL }
    },
    { &hf_rtps_sm_entity_id_kind, {
        "entityKind",
        "rtps.sm.entityId.entityKind",
        FT_UINT8,
        BASE_HEX,
        VALS(entity_kind_vals),
        0,
        "'entityKind' field of the object entity ID",
        HFILL }
    },

    { &hf_rtps_sm_rdentity_id, {
        "readerEntityId",
        "rtps.sm.rdEntityId",
        FT_UINT32,
        BASE_HEX,
        VALS(entity_id_vals),
        0,
        "Reader entity ID as it appears in a submessage",
        HFILL }
    },
    { &hf_rtps_sm_rdentity_id_key, {
        "readerEntityKey",
        "rtps.sm.rdEntityId.entityKey",
        FT_UINT24,
        BASE_HEX,
        NULL,
        0,
        "'entityKey' field of the reader entity ID",
        HFILL }
    },
    { &hf_rtps_sm_rdentity_id_kind, {
        "readerEntityKind",
        "rtps.sm.rdEntityId.entityKind",
        FT_UINT8,
        BASE_HEX,
        VALS(entity_kind_vals),
        0,
        "'entityKind' field of the reader entity ID",
        HFILL }
    },

    { &hf_rtps_sm_wrentity_id, {
        "writerEntityId",
        "rtps.sm.wrEntityId",
        FT_UINT32,
        BASE_HEX,
        VALS(entity_id_vals),
        0,
        "Writer entity ID as it appears in a submessage",
        HFILL }
    },
    { &hf_rtps_sm_wrentity_id_key, {
        "writerEntityKey",
        "rtps.sm.wrEntityId.entityKey",
        FT_UINT24,
        BASE_HEX,
        NULL,
        0,
        "'entityKey' field of the writer entity ID",
        HFILL }
    },
    { &hf_rtps_sm_wrentity_id_kind, {
        "writerEntityKind",
        "rtps.sm.wrEntityId.entityKind",
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
        "rtps.sm.seqNumber",
        FT_INT64,
        BASE_DEC,
        NULL,
        0,
        "Writer sequence number",
        HFILL }
    },

    { &hf_rtps_info_src_ip, {
        "appIpAddress",
        "rtps.info_src.ip",
        FT_IPv4,
        BASE_NONE,
        NULL,
        0,
        NULL,
        HFILL }
    },

    { &hf_rtps_info_src_unused, {
        "Unused",
        "rtps.info_src.unused",
        FT_UINT32,
        BASE_HEX,
        NULL,
        0,
        NULL,
        HFILL }
    },

    /* Parameter Id -------------------------------------------------------- */
    { &hf_rtps_parameter_id, {
        "parameterId",
        "rtps.param.id",
        FT_UINT16,
        BASE_HEX,
        VALS(parameter_id_vals),
        0,
        "Parameter Id",
        HFILL }
    },

    { &hf_rtps_parameter_id_v2, {
        "parameterId",
        "rtps.param.id",
        FT_UINT16,
        BASE_HEX,
        VALS(parameter_id_v2_vals),
        0,
        "Parameter Id",
        HFILL }
    },

    /* Parameter Length ---------------------------------------------------- */
    { &hf_rtps_parameter_length, {
        "parameterLength",
        "rtps.param.length",
        FT_UINT16,
        BASE_DEC,
        NULL,
        0,
        "Parameter Length",
        HFILL }
    },

    /* Parameter / Topic --------------------------------------------------- */
    { &hf_rtps_param_topic_name, {
        "topic",
        "rtps.param.topicName",
        FT_STRINGZ,
        BASE_NONE,
        NULL,
        0,
        "String representing the value value of a PID_TOPIC parameter",
        HFILL }
    },

    /* Parameter / Strength ------------------------------------------------ */
    { &hf_rtps_param_strength, {
        "strength",
        "rtps.param.strength",
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
        "rtps.param.typeName",
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
        "rtps.param.userData",
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
        "rtps.param.groupData",
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
        "rtps.param.topicData",
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
        "rtps.param.contentFilterName",
        FT_STRINGZ,
        BASE_NONE,
        NULL,
        0,
        "Value of the content filter name as sent in a PID_CONTENT_FILTER_PROPERTY parameter",
        HFILL }
    },
    { &hf_rtps_param_related_topic_name, {
        "relatedTopicName",
        "rtps.param.relatedTopicName",
        FT_STRINGZ,
        BASE_NONE,
        NULL,
        0,
        "Value of the related topic name as sent in a PID_CONTENT_FILTER_PROPERTY parameter",
        HFILL }
    },
    { &hf_rtps_param_filter_name, {
        "filterName",
        "rtps.param.filterName",
        FT_STRINGZ,
        BASE_NONE,
        NULL,
        0,
        "Value of the filter name as sent in a PID_CONTENT_FILTER_PROPERTY parameter",
        HFILL }
    },

    { &hf_rtps_durability_service_cleanup_delay,
      { "Service Cleanup Delay", "rtps.durability.service_cleanup_delay",
        FT_ABSOLUTE_TIME, ABSOLUTE_TIME_UTC, NULL, 0,
        "Time using the NTP standard format", HFILL }
    },

    { &hf_rtps_liveliness_lease_duration,
      { "Lease Duration", "rtps.liveliness.lease_duration",
        FT_ABSOLUTE_TIME, ABSOLUTE_TIME_UTC, NULL, 0,
        "Time using the NTP standard format", HFILL }
    },

    { &hf_rtps_participant_lease_duration,
      { "Duration", "rtps.participant_lease_duration",
        FT_ABSOLUTE_TIME, ABSOLUTE_TIME_UTC, NULL, 0,
        "Time using the NTP standard format", HFILL }
    },

    { &hf_rtps_time_based_filter_minimum_separation,
      { "Minimum Separation", "rtps.time_based_filter.minimum_separation",
        FT_ABSOLUTE_TIME, ABSOLUTE_TIME_UTC, NULL, 0,
        "Time using the NTP standard format", HFILL }
    },

    { &hf_rtps_reliability_max_blocking_time,
      { "Max Blocking Time", "rtps.reliability.max_blocking_time",
        FT_ABSOLUTE_TIME, ABSOLUTE_TIME_UTC, NULL, 0,
        "Time using the NTP standard format", HFILL }
    },

    { &hf_rtps_deadline_period,
      { "Period", "rtps.deadline_period",
        FT_ABSOLUTE_TIME, ABSOLUTE_TIME_UTC, NULL, 0,
        "Time using the NTP standard format", HFILL }
    },

    { &hf_rtps_latency_budget_duration,
      { "Duration", "rtps.latency_budget.duration",
        FT_ABSOLUTE_TIME, ABSOLUTE_TIME_UTC, NULL, 0,
        "Time using the NTP standard format", HFILL }
    },

    { &hf_rtps_lifespan_duration,
      { "Duration", "rtps.lifespan",
        FT_ABSOLUTE_TIME, ABSOLUTE_TIME_UTC, NULL, 0,
        "Time using the NTP standard format", HFILL }
    },

    { &hf_rtps_persistence,
      { "Persistence", "rtps.persistence",
        FT_ABSOLUTE_TIME, ABSOLUTE_TIME_UTC, NULL, 0,
        "Time using the NTP standard format", HFILL }
    },

    { &hf_rtps_info_ts_timestamp,
      { "Timestamp", "rtps.info_ts.timestamp",
        FT_ABSOLUTE_TIME, ABSOLUTE_TIME_UTC, NULL, 0,
        "Time using the NTP standard format", HFILL }
    },

    { &hf_rtps_locator_kind,
      { "Kind", "rtps.locator.kind",
        FT_UINT32, BASE_HEX, VALS(rtps_locator_kind_vals), 0,
        NULL, HFILL }
    },

    { &hf_rtps_locator_port,
      { "Port", "rtps.locator.port",
        FT_INT32, BASE_DEC, NULL, 0,
        NULL, HFILL }
    },

    { &hf_rtps_locator_ipv4,
      { "Address", "rtps.locator.ipv4",
        FT_IPv4, BASE_NONE, NULL, 0,
        NULL, HFILL }
    },

    { &hf_rtps_locator_ipv6,
      { "Address", "rtps.locator.ipv6",
        FT_IPv6, BASE_NONE, NULL, 0,
        NULL, HFILL }
    },

    { &hf_rtps_participant_builtin_endpoints,
      { "BuiltIn Endpoint", "rtps.participant_builtin_endpoints",
        FT_UINT32, BASE_HEX, NULL, 0,
        NULL, HFILL }
    },

    { &hf_rtps_participant_manual_liveliness_count,
      { "Manual Liveliness Count", "rtps.participant_manual_liveliness_count",
        FT_UINT32, BASE_HEX, NULL, 0,
        NULL, HFILL }
    },

    { &hf_rtps_history_depth,
      { "Depth", "rtps.history_depth",
        FT_INT32, BASE_DEC, NULL, 0,
        NULL, HFILL }
    },

    { &hf_rtps_resource_limit_max_samples,
      { "Max Samples", "rtps.resource_limit.max_samples",
        FT_INT32, BASE_DEC, NULL, 0,
        NULL, HFILL }
    },

    { &hf_rtps_resource_limit_max_instances,
      { "Max Instances", "rtps.resource_limit.max_instances",
        FT_INT32, BASE_DEC, NULL, 0,
        NULL, HFILL }
    },

    { &hf_rtps_resource_limit_max_samples_per_instances,
      { "Max Samples Per Instance", "rtps.resource_limit.max_samples_per_instance",
        FT_INT32, BASE_DEC, NULL, 0,
        NULL, HFILL }
    },

    { &hf_rtps_filter_bitmap,
      { "Filter Bitmap", "rtps.filter_bitmap",
        FT_UINT32, BASE_HEX, NULL, 0,
        NULL, HFILL }
    },

    { &hf_rtps_type_checksum,
      { "Checksum", "rtps.type_checksum",
        FT_UINT32, BASE_HEX, NULL, 0,
        NULL, HFILL }
    },

    { &hf_rtps_queue_size,
      { "queueSize", "rtps.queue_size",
        FT_UINT32, BASE_HEX, NULL, 0,
        NULL, HFILL }
    },

    { &hf_rtps_acknack_counter,
      { "Counter", "rtps.acknack.counter",
        FT_INT32, BASE_DEC, NULL, 0,
        NULL, HFILL }
    },

    { &hf_rtps_durability_service_history_kind,
      { "History Kind", "rtps.durability_service.history_kind",
        FT_UINT32, BASE_HEX, VALS(history_qos_vals), 0,
        NULL, HFILL }
    },

    { &hf_rtps_durability_service_history_depth,
      { "History Depth", "rtps.durability_service.history_depth",
        FT_INT32, BASE_DEC, NULL, 0,
        NULL, HFILL }
    },

    { &hf_rtps_durability_service_max_samples,
      { "Max Samples", "rtps.durability_service.max_samples",
        FT_INT32, BASE_DEC, NULL, 0,
        NULL, HFILL }
    },

    { &hf_rtps_durability_service_max_instances,
      { "Max Instances", "rtps.durability_service.max_instances",
        FT_INT32, BASE_DEC, NULL, 0,
        NULL, HFILL }
    },

    { &hf_rtps_durability_service_max_samples_per_instances,
      { "Max Samples Per Instance", "rtps.durability_service.max_samples_per_instance",
        FT_INT32, BASE_DEC, NULL, 0,
        NULL, HFILL }
    },

    { &hf_rtps_liveliness_kind,
      { "Kind", "rtps.liveliness.kind",
        FT_UINT32, BASE_HEX, VALS(liveliness_qos_vals), 0,
        NULL, HFILL }
    },

    { &hf_rtps_manager_key,
      { "Key", "rtps.manager_key",
        FT_UINT32, BASE_HEX, NULL, 0,
        NULL, HFILL }
    },

    { &hf_rtps_locator_udp_v4,
      { "Address", "rtps.locator_udp_v4.ip",
        FT_IPv4, BASE_NONE, NULL, 0,
        NULL, HFILL }
    },

    { &hf_rtps_locator_udp_v4_port,
      { "Port", "rtps.locator_udp_v4.port",
        FT_UINT32, BASE_HEX, NULL, 0,
        NULL, HFILL }
    },

    { &hf_param_ip_address,
      { "Address", "rtps.param.ip_address",
        FT_IPv4, BASE_NONE, NULL, 0,
        NULL, HFILL }
    },

    { &hf_rtps_param_port,
      { "Port", "rtps.param.port",
        FT_UINT32, BASE_HEX, NULL, 0,
        NULL, HFILL }
    },

    { &hf_rtps_expects_inline_qos,
      { "Inline QoS", "rtps.expects_inline_qos",
        FT_BOOLEAN, 8, TFS(&tfs_true_false), 0,
        NULL, HFILL }
    },

    { &hf_rtps_presentation_coherent_access,
      { "Coherent Access", "rtps.presentation.coherent_access",
        FT_BOOLEAN, 8, TFS(&tfs_true_false), 0,
        NULL, HFILL }
    },

    { &hf_rtps_presentation_ordered_access,
      { "Ordered Access", "rtps.presentation.ordered_access",
        FT_BOOLEAN, 8, TFS(&tfs_true_false), 0,
        NULL, HFILL }
    },

    { &hf_rtps_expects_ack,
      { "expectsAck", "rtps.expects_ack",
        FT_BOOLEAN, 8, TFS(&tfs_true_false), 0,
        NULL, HFILL }
    },

    { &hf_rtps_reliability_kind,
      { "Kind", "rtps.reliability_kind",
        FT_UINT32, BASE_HEX, VALS(reliability_qos_vals), 0,
        NULL, HFILL }
    },

    { &hf_rtps_durability,
      { "Durability", "rtps.durability",
        FT_UINT32, BASE_HEX, VALS(durability_qos_vals), 0,
        NULL, HFILL }
    },

    { &hf_rtps_ownership,
      { "Kind", "rtps.ownership",
        FT_UINT32, BASE_HEX, VALS(ownership_qos_vals), 0,
        NULL, HFILL }
    },

    { &hf_rtps_presentation_access_scope,
      { "Access Scope", "rtps.presentation.access_scope",
        FT_UINT32, BASE_HEX, VALS(presentation_qos_vals), 0,
        NULL, HFILL }
    },

    { &hf_rtps_destination_order,
      { "Kind", "rtps.destination_order",
        FT_UINT32, BASE_HEX, VALS(destination_order_qos_vals), 0,
        NULL, HFILL }
    },

    { &hf_rtps_history_kind,
      { "Kind", "rtps.history.kind",
        FT_UINT32, BASE_HEX, VALS(history_qos_vals), 0,
        NULL, HFILL }
    },

    { &hf_rtps_data_status_info,
      { "statusInfo", "rtps.data.status_info",
        FT_UINT32, BASE_HEX, NULL, 0,
        NULL, HFILL }
    },

    { &hf_rtps_param_serialize_encap_kind,
      { "encapsulation kind", "rtps.param.serialize.encap_kind",
        FT_UINT16, BASE_HEX, VALS(encapsulation_id_vals), 0,
        NULL, HFILL }
    },

    { &hf_rtps_param_serialize_encap_len,
      { "encapsulation options", "rtps.param.serialize.encap_len",
        FT_UINT16, BASE_HEX, NULL, 0,
        NULL, HFILL }
    },

    { &hf_rtps_param_status_info,
      { "statusInfo", "rtps.param.statusInfo",
        FT_UINT32, BASE_HEX, NULL, 0,
        "State information of the data object to which the message apply (i.e. lifecycle)",
        HFILL }
    },

    { &hf_rtps_param_transport_priority,
      { "Value", "rtps.param.transport_priority",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }
    },

    { &hf_rtps_param_type_max_size_serialized,
      { "Value", "rtps.param.type_max_size_serialized",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }
    },

    { &hf_rtps_param_entity_name,
      { "entity", "rtps.param.entityName",
        FT_STRINGZ, BASE_NONE, NULL, 0,
        "String representing the name of the entity addressed by the submessage",
        HFILL }
    },

    { &hf_rtps_disable_positive_ack,
      { "disablePositiveAcks", "rtps.disable_positive_ack",
        FT_BOOLEAN, 8, TFS(&tfs_true_false), 0,
        NULL, HFILL }
    },

    { &hf_rtps_participant_guid,
      { "Participant GUID", "rtps.param.participant_guid",
        FT_UINT64, BASE_HEX, NULL, 0,
        NULL, HFILL }
    },

    { &hf_rtps_group_guid,
      { "Group GUID", "rtps.param.group_guid",
        FT_UINT64, BASE_HEX, NULL, 0,
        NULL, HFILL }
    },

    { &hf_rtps_endpoint_guid,
      { "Endpoint GUID", "rtps.param.endpoint_guid",
        FT_UINT64, BASE_HEX, NULL, 0,
        NULL, HFILL }
    },

    { &hf_rtps_param_host_id,
      { "host_id", "rtps.param.guid.hostId",
        FT_UINT32, BASE_HEX, NULL, 0,
        NULL, HFILL }
    },

    { &hf_rtps_param_app_id,
      { "appId", "rtps.param.guid.appId",
        FT_UINT32, BASE_HEX, NULL, 0,
        NULL, HFILL }
    },

    { &hf_rtps_param_instance_id,
      { "instanceId", "rtps.param.guid.instanceId",
        FT_UINT24, BASE_HEX, NULL, 0,
        NULL, HFILL }
    },

    { &hf_rtps_param_app_kind,
      { "instanceId", "rtps.param.guid.appKind",
        FT_UINT8, BASE_HEX, NULL, 0,
        NULL, HFILL }
    },

    { &hf_rtps_param_entity,
      { "entityId", "rtps.param.guid.entityId",
        FT_UINT32, BASE_HEX, VALS(entity_id_vals), 0,
        NULL, HFILL }
    },

    { &hf_rtps_param_entity_key,
      { "entityKey", "rtps.param.guid.entityKey",
        FT_UINT24, BASE_HEX, NULL, 0,
        NULL, HFILL }
    },

    { &hf_rtps_param_hf_entity_kind,
      { "entityKind", "rtps.param.guid.entityKind",
        FT_UINT8, BASE_HEX, VALS(entity_kind_vals), 0,
        NULL, HFILL }
    },

    { &hf_rtps_param_counter,
      { "Counter", "rtps.param.guid.counter",
        FT_UINT32, BASE_HEX, NULL, 0,
        NULL, HFILL }
    },

    { &hf_rtps_data_frag_number,
      { "fragmentStartingNum", "rtps.data_frag.number",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }
    },

    { &hf_rtps_data_frag_sample_size,
      { "sampleSize", "rtps.data_frag.sample_size",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }
    },

    { &hf_rtps_data_frag_num_fragments,
      { "fragmentsInSubmessage", "rtps.data_frag.num_fragments",
        FT_UINT16, BASE_DEC, NULL, 0,
        NULL, HFILL }
    },

    { &hf_rtps_data_frag_size,
      { "fragmentSize", "rtps.data_frag.size",
        FT_UINT16, BASE_DEC, NULL, 0,
        NULL, HFILL }
    },

    { &hf_rtps_nokey_data_frag_number,
      { "fragmentStartingNum", "rtps.nokey_data_frag.number",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }
    },

    { &hf_rtps_nokey_data_frag_num_fragments,
      { "fragmentsInSubmessage", "rtps.nokey_data_frag.num_fragments",
        FT_UINT16, BASE_DEC, NULL, 0,
        NULL, HFILL }
    },

    { &hf_rtps_nokey_data_frag_size,
      { "fragmentSize", "rtps.nokey_data_frag.size",
        FT_UINT16, BASE_DEC, NULL, 0,
        NULL, HFILL }
    },

    { &hf_rtps_nack_frag_count,
      { "Count", "rtps.nack_frag.count",
        FT_INT32, BASE_DEC, NULL, 0,
        NULL, HFILL }
    },

    { &hf_rtps_heartbeat_frag_number,
      { "lastFragmentNum", "rtps.heartbeat_frag.number",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }
    },

    { &hf_rtps_heartbeat_frag_count,
      { "Count", "rtps.heartbeat_frag.count",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }
    },

    { &hf_rtps_heartbeat_batch_count,
      { "Count", "rtps.heartbeat_batch.count",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }
    },

    { &hf_rtps_data_serialize_data, {
        "serializedData", "rtps.data.serialize_data",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }
    },

    { &hf_rtps_data_batch_timestamp,
      { "Timestamp", "rtps.data_batch.timestamp",
        FT_ABSOLUTE_TIME, ABSOLUTE_TIME_UTC, NULL, 0,
        "Time using the NTP standard format", HFILL }
    },

    { &hf_rtps_data_batch_offset_to_last_sample_sn,
      { "offsetToLastSampleSN", "rtps.data_batch.offset_to_last_sample_sn",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }
    },

    { &hf_rtps_data_batch_sample_count,
      { "batchSampleCount", "rtps.data_batch.sample_count",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }
    },

    { &hf_rtps_data_batch_offset_sn,
      { "offsetSN", "rtps.data_batch.offset_sn",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }
    },

    { &hf_rtps_data_batch_octets_to_sl_encap_id,
      { "octetsToSLEncapsulationId", "rtps.data_batch.octets_to_sl_encap_id",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }
    },

    { &hf_rtps_data_batch_serialized_data_length,
      { "serializedDataLength", "rtps.data_batch.serialized_data_length",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }
    },

    { &hf_rtps_data_batch_octets_to_inline_qos,
      { "octetsToInlineQos", "rtps.data_batch.octets_to_inline_qos",
        FT_UINT16, BASE_DEC, NULL, 0,
        NULL, HFILL }
    },

    { &hf_rtps_fragment_number_base64,
      { "bitmapBase", "rtps.fragment_number.base",
        FT_UINT64, BASE_DEC, NULL, 0,
        NULL, HFILL }
    },

    { &hf_rtps_fragment_number_base,
      { "bitmapBase", "rtps.fragment_number.base",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }
    },

    { &hf_rtps_fragment_number_num_bits,
      { "numBits", "rtps.fragment_number.num_bits",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }
    },

    { &hf_rtps_bitmap_num_bits,
      { "numBits", "rtps.bitmap.num_bits",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }
    },

    { &hf_rtps_param_partition_num,
      { "Size", "rtps.param.partition_num",
        FT_INT32, BASE_DEC, NULL, 0,
        NULL, HFILL }
    },

    { &hf_rtps_param_filter_parameters_num,
      { "Size", "rtps.param.filter_parameters_num",
        FT_INT32, BASE_DEC, NULL, 0,
        NULL, HFILL }
    },

    { &hf_rtps_param_partition,
      { "name", "rtps.param.partition",
        FT_STRING, BASE_NONE, NULL, 0,
        NULL, HFILL }
    },

    { &hf_rtps_param_filter_expression,
      { "filterExpression", "rtps.param.filter_expression",
        FT_STRING, BASE_NONE, NULL, 0,
        NULL, HFILL }
    },

    { &hf_rtps_param_filter_parameters,
      { "filterParameters", "rtps.param.filter_parameters",
        FT_STRING, BASE_NONE, NULL, 0,
        NULL, HFILL }
    },

    { &hf_rtps_locator_filter_list_num_channels,
      { "numberOfChannels", "rtps.param.locator_filter_list.num_channels",
        FT_INT32, BASE_DEC, NULL, 0,
        NULL, HFILL }
    },

    { &hf_rtps_locator_filter_list_filter_name,
      { "filterName", "rtps.param.locator_filter_list.filter_name",
        FT_STRING, BASE_NONE, NULL, 0,
        NULL, HFILL }
    },

    { &hf_rtps_locator_filter_list_filter_exp,
      { "filterExpression", "rtps.param.locator_filter_list.filter_exp",
        FT_STRING, BASE_NONE, NULL, 0,
        NULL, HFILL }
    },

    { &hf_rtps_extra_flags,
      { "Extra flags", "rtps.extra_flags",
        FT_UINT16, BASE_HEX, NULL, 0xFFFF,
        NULL, HFILL }
    },

    { &hf_rtps_param_builtin_endpoint_set,
      { "Builtin endpoint set", "rtps.param.builtin_endpoint_set",
        FT_UINT32, BASE_HEX, NULL, 0xFFFFFFFF,
        NULL, HFILL }
    },

    { &hf_rtps_param_plugin_promiscuity_kind,
      { "promiscuityKind", "rtps.param.plugin_promiscuity_kind",
        FT_UINT32, BASE_HEX, VALS(plugin_promiscuity_kind_vals), 0,
        NULL, HFILL }
    },

    { &hf_rtps_param_service_kind,
      { "serviceKind", "rtps.param.service_kind",
        FT_UINT32, BASE_HEX, VALS(service_kind_vals), 0,
        NULL, HFILL }
    },

    /* Finally the raw issue data ------------------------------------------ */
    { &hf_rtps_issue_data, {
        "serializedData",
        "rtps.issueData",
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
    &ett_rtps_generic_guid,
    &ett_rtps_rdentity,
    &ett_rtps_wrentity,
    &ett_rtps_guid_prefix,
    &ett_rtps_app_id,
    &ett_rtps_locator_udp_v4,
    &ett_rtps_locator,
    &ett_rtps_locator_list,
    &ett_rtps_ntp_time,
    &ett_rtps_bitmap,
    &ett_rtps_seq_string,
    &ett_rtps_seq_ulong,
    &ett_rtps_resource_limit,
    &ett_rtps_durability_service,
    &ett_rtps_liveliness,
    &ett_rtps_manager_key,
    &ett_rtps_serialized_data,
    &ett_rtps_locator_filter_channel,
    &ett_rtps_part_message_data,
    &ett_rtps_sample_info_list,
    &ett_rtps_sample_info,
    &ett_rtps_sample_batch_list
  };

  static ei_register_info ei[] = {
     { &ei_rtps_sm_octets_to_next_header_error, { "rtps.sm.octetsToNextHeader.error", PI_PROTOCOL, PI_WARN, "(Error: bad length)", EXPFILL }},
     { &ei_rtps_locator_port, { "rtps.locator.port.invalid", PI_PROTOCOL, PI_WARN, "Invalid Port", EXPFILL }},
     { &ei_rtps_ip_invalid, { "rtps.ip_invalid", PI_PROTOCOL, PI_WARN, "IPADDRESS_INVALID_STRING", EXPFILL }},
     { &ei_rtps_port_invalid, { "rtps.port_invalid", PI_PROTOCOL, PI_WARN, "PORT_INVALID_STRING", EXPFILL }},
     { &ei_rtps_parameter_value_invalid, { "rtps.parameter_value_too_small", PI_PROTOCOL, PI_WARN, "ERROR: Parameter value too small", EXPFILL }},
     { &ei_rtps_parameter_not_decoded, { "rtps.parameter_not_decoded", PI_PROTOCOL, PI_WARN, "[DEPRECATED] - Parameter not decoded", EXPFILL }},
     { &ei_rtps_sm_octets_to_next_header_not_zero, { "rtps.sm.octetsToNextHeader.not_zero", PI_PROTOCOL, PI_WARN, "Should be ZERO", EXPFILL }},
     { &ei_rtps_extra_bytes, { "rtps.extra_bytes", PI_MALFORMED, PI_ERROR, "Don't know how to decode those extra bytes: %d", EXPFILL }},
     { &ei_rtps_missing_bytes, { "rtps.missing_bytes", PI_MALFORMED, PI_ERROR, "Not enough bytes to decode", EXPFILL }},
     { &ei_rtps_more_samples_available, { "rtps.more_samples_available", PI_PROTOCOL, PI_NOTE, "More samples available. Configure this limit from preferences dialog", EXPFILL }},
  };

  module_t *rtps_module;
  expert_module_t* expert_rtps;

  proto_rtps = proto_register_protocol(
                        "Real-Time Publish-Subscribe Wire Protocol",
                        "RTPS",
                        "rtps");
  proto_register_field_array(proto_rtps, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));
  expert_rtps = expert_register_protocol(proto_rtps);
  expert_register_field_array(expert_rtps, ei, array_length(ei));

  /* Registers the control in the preference panel */
  rtps_module = prefs_register_protocol(proto_rtps, NULL);
  prefs_register_uint_preference(rtps_module, "max_batch_samples_dissected",
            "Max samples dissected for DATA_BATCH",
            "Specifies the maximum number of samples dissected in "
            "a DATA_BATCH submessage. Increasing this value may affect "
            "performances if the trace has a lot of big batched samples.",
            10, &rtps_max_batch_samples_dissected);
}


void proto_reg_handoff_rtps(void) {
 heur_dissector_add("udp", dissect_rtps_udp, proto_rtps);
 heur_dissector_add("tcp", dissect_rtps_tcp, proto_rtps);
}

