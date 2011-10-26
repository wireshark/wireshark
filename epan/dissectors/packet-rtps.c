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


#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <glib.h>
#include <epan/packet.h>
#include <epan/addr_resolv.h>

#include "packet-rtps.h"

/* Size of the temp buffers used to format various part of the protocol.
 * Note: Some of those values are bigger than expected. The reason is
 *       because the string buffer can also contains decoded values.
 *       I.e. port size is an integer, but for value 0x0000, it is interpreted
 *       as a string "PORT_INVALID (0x00000000)"
 */
#define MAX_FLAG_SIZE           (20)
#define MAX_GUID_PREFIX_SIZE    (128)
#define MAX_GUID_SIZE           (160)
#define MAX_VENDOR_ID_SIZE      (128)
#define MAX_NTP_TIME_SIZE       (128)
#define MAX_PORT_SIZE           (32)
#define MAX_PARAM_SIZE          (256)
#define MAX_LOCATOR_SIZE        (200)
#define MAX_IPV6_SIZE           (100)
#define MAX_BITMAP_SIZE         (200)
#define MAX_LABEL_SIZE          (64)
#define MAX_IPV4_ADDRESS_SIZE   (64)

/* Max octects printed on the parameter root for a sequence of octects */
#define MAX_SEQ_OCTETS_PRINTED  (20)


static const char * const SM_EXTRA_RPLUS  = "(r+)";
static const char * const SM_EXTRA_RMINUS = "(r-)";
static const char * const SM_EXTRA_WPLUS  = "(w+)";
static const char * const SM_EXTRA_WMINUS = "(w-)";
static const char * const SM_EXTRA_PPLUS  = "(p+)";
static const char * const SM_EXTRA_PMINUS = "(p-)";
static const char * const SM_EXTRA_TPLUS  = "(t+)";
static const char * const SM_EXTRA_TMINUS = "(t-)";

/* This structure is used to keep a list of submessages for the current
 * packet. The list is ordered by position of the submessage Id inside
 * the packet.
 * Submessages of the same kind are grouped together in one record.
 */
struct SMCounterRecord {
  int                      id;          /* PAD, DATA, ... */
  const char *             extra;       /* (r+, w+)... */
  struct SMCounterRecord * next;        /* Ptr to next */
};




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
static int hf_rtps_sm_flags                     = -1;
static int hf_rtps_sm_octets_to_next_header     = -1;
static int hf_rtps_sm_guid_prefix               = -1;
static int hf_rtps_sm_host_id                   = -1;
static int hf_rtps_sm_app_id                    = -1;
static int hf_rtps_sm_instance_id               = -1;
static int hf_rtps_sm_app_kind                  = -1;
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
static int hf_rtps_param_strength               = -1;
static int hf_rtps_param_type_name              = -1;
static int hf_rtps_param_user_data              = -1;
static int hf_rtps_param_group_data             = -1;
static int hf_rtps_param_topic_data             = -1;
static int hf_rtps_param_content_filter_name    = -1;
static int hf_rtps_param_related_topic_name     = -1;
static int hf_rtps_param_filter_name            = -1;
static int hf_rtps_issue_data                   = -1;

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
static gint ett_rtps_app_id                     = -1;
static gint ett_rtps_locator_udp_v4             = -1;
static gint ett_rtps_locator                    = -1;
static gint ett_rtps_locator_list               = -1;
static gint ett_rtps_ntp_time                   = -1;
static gint ett_rtps_bitmap                     = -1;
static gint ett_rtps_seq_string                 = -1;
static gint ett_rtps_seq_ulong                  = -1;

/***************************************************************************/
/* Value-to-String Tables */
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


static const value_string submessage_id_vals[] = {
  { PAD,                                "PAD" },
  { DATA,                               "DATA" },
  { NOKEY_DATA,                         "NOKEY_DATA" },
  { ACKNACK,                            "ACKNACK" },
  { HEARTBEAT,                          "HEARTBEAT" },
  { GAP,                                "GAP" },
  { INFO_TS,                            "INFO_TS" },
  { INFO_SRC,                           "INFO_SRC" },
  { INFO_REPLY_IP4,                     "INFO_REPLY_IP4" },
  { INFO_DST,                           "INFO_DST" },
  { INFO_REPLY,                         "INFO_REPLY" },
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
  { PID_DEFAULT_EXPECTS_INLINE_QOS,     "PID_DEFAULT_EXPECTS_INLINE_QOS" },
  { PID_METATRAFFIC_UNICAST_IPADDRESS,  "PID_METATRAFFIC_UNICAST_IPADDRESS" },
  { PID_PARTICIPANT_BUILTIN_ENDPOINTS,  "PID_PARTICIPANT_BUILTIN_ENDPOINTS" },
  { PID_CONTENT_FILTER_PROPERTY,        "PID_CONTENT_FILTER_PROPERTY" },
  { PID_PROPERTY_LIST,                  "PID_PROPERTY_LIST" },
  { PID_FILTER_SIGNATURE,               "PID_FILTER_SIGNATURE" },
  { PID_COHERENT_SET,                   "PID_COHERENT_SET" },
  { PID_TYPECODE,                       "PID_TYPECODE" },
  { PID_PARTICIPANT_GUID,               "PID_PARTICIPANT_GUID" },
  { PID_PARTICIPANT_ENTITY_ID,          "PID_PARTICIPANT_ENTITY_ID" },
  { PID_GROUP_GUID,                     "PID_GROUP_GUID" },
  { PID_GROUP_ENTITY_ID,                "PID_GROUP_ENTITY_ID" },
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
  { 'U', "Unregister flag" },                   /* Bit 5 */
  { 'Q', "Inline QoS" },                        /* Bit 4 */
  { 'H', "Hash key flag" },                     /* Bit 3 */
  { 'A', "Alive flag" },                        /* Bit 2 */
  { 'D', "Data present" },                      /* Bit 1 */
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





/***************************************************************************
 * Function prototypes
 * ~~~~~~~~~~~~~~~~~~~
 */

/* Sm management */
static struct SMCounterRecord * sm_counter_add(struct SMCounterRecord *, guint8, const char * const extra);
static void                     sm_counter_free(struct SMCounterRecord *);


/* Utility to add elements to the protocol tree */
static void rtps_util_format_ipv6(guint8 *, guint8 *, gint);
static void rtps_util_add_protocol_version(proto_tree *, tvbuff_t *, gint);
static void rtps_util_add_vendor_id(proto_tree *, tvbuff_t *,
                        gint, guint8 *, gint);
static void rtps_util_add_locator_t(proto_tree *, tvbuff_t *,
                        gint, int, const guint8 *, guint8 *, gint);
static void rtps_util_add_locator_list(proto_tree *, tvbuff_t *,
                        gint, const guint8 *, int);
static void rtps_util_add_ipv4_address_t(proto_tree *, tvbuff_t *,
                        gint, int, const guint8 *, guint8 *, gint);
static void rtps_util_add_locator_udp_v4(proto_tree *, tvbuff_t *,
                        gint, const guint8 *, int);
static void rtps_util_add_guid_prefix(proto_tree *, tvbuff_t *,
                        gint, int, int, int, int, int, const guint8 *,
                        guint8 *, gint);
static int rtps_util_add_entity_id(proto_tree *, tvbuff_t *,
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
static void rtps_util_add_long(proto_tree *, tvbuff_t *,
                        gint, int, int, gboolean, gboolean, const char *,
                        guint8 *, size_t);
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
static void rtps_util_decode_flags(proto_tree *, tvbuff_t *,
                        gint, guint8, const struct Flag_definition *);
static gint rtps_util_add_seq_ulong(proto_tree *, tvbuff_t *,
                        gint, int, int, int, int, char *);



/* The parameter dissector */
static gint dissect_parameter_sequence(proto_tree *, tvbuff_t *,
                        gint, int, int, const char *);

/* Sub-message dissector functions */
static void dissect_DATA(tvbuff_t *tvb,gint offset,guint8 flags,
                        gboolean little_endian,int next_submsg_offset,
                        proto_tree *rtps_submessage_tree,
                        const char **sm_extra);

static void dissect_NOKEY_DATA(tvbuff_t *tvb,gint offset,guint8 flags,
                        gboolean little_endian,int next_submsg_offset,
                        proto_tree *rtps_submessage_tree);

static void dissect_ACKNACK(tvbuff_t *tvb,gint offset,guint8 flags,
                        gboolean little_endian,int next_submsg_offset,
                        proto_tree *rtps_submessage_tree);

static void dissect_HEARTBEAT(tvbuff_t *tvb,gint offset,guint8 flags,
                        gboolean little_endian,int next_submsg_offset,
                        proto_tree *rtps_submessage_tree);

static void dissect_GAP(tvbuff_t *tvb,gint offset,guint8 flags,
                        gboolean little_endian,int next_submsg_offset,
                        proto_tree *rtps_submessage_tree);

static void dissect_INFO_TS(tvbuff_t *tvb,gint offset,guint8 flags,
                        gboolean little_endian,int next_submsg_offset,
                        proto_tree *rtps_submessage_tree);

static void dissect_INFO_SRC(tvbuff_t *tvb,gint offset,guint8 flags,
                        gboolean little_endian,int next_submsg_offset,
                        proto_tree *rtps_submessage_tree);

static void dissect_INFO_REPLY_IP4(tvbuff_t *tvb,gint offset,guint8 flags,
                        gboolean little_endian,int next_submsg_offset,
                        proto_tree *rtps_submessage_tree);

static void dissect_INFO_DST(tvbuff_t *tvb,gint offset,guint8 flags,
                        gboolean little_endian,int next_submsg_offset,
                        proto_tree *rtps_submessage_tree);

static void dissect_INFO_REPLY(tvbuff_t *tvb,gint offset,guint8 flags,
                        gboolean little_endian,int next_submsg_offset,
                        proto_tree *rtps_submessage_tree);

/* The main packet dissector */
static gboolean dissect_rtps(tvbuff_t *, packet_info *, proto_tree *);


/***************************************************************************/
/* Inline macros */

#define NEXT_guint16(tvb, offset, le)    \
                (le ? tvb_get_letohs(tvb, offset) : tvb_get_ntohs(tvb, offset))

#define NEXT_guint32(tvb, offset, le)    \
                (le ? tvb_get_letohl(tvb, offset) : tvb_get_ntohl(tvb, offset))


/* *********************************************************************** */
/* Adds a new record to the SMCounterRecord archive
 * It always inserts to the end of the list. Insert is not performed if
 * the last element is like the current one.
 * Parameters:
 *   last = ptr to the last element or NULL if the list is empty
 *
 * Returns:
 *   ptr to the last element of the list or NULL if out of memory occurred.
 */
static struct SMCounterRecord * sm_counter_add(
                        struct SMCounterRecord *last,
                        guint8  submessage,
                        const char * const extra) {     /* Can be NULL */
#if 0
  if ((last == NULL) || (last->id != submessage)) {
    struct SMCounterRecord *ptr;

    /* Add message */
    ptr = (struct SMCounterRecord *)g_malloc(sizeof(struct SMCounterRecord));
    if (ptr == NULL) {
      return NULL;
    }
    ptr->id = submessage;
    ptr->counter = 1;
    ptr->next = NULL;
    if (last) {
      last->next = ptr;
    }
    return ptr;
  }

  last->counter++;
#endif

    struct SMCounterRecord *ptr;
    ptr = (struct SMCounterRecord *)g_malloc(sizeof(struct SMCounterRecord));
    if (ptr == NULL) {
      return NULL;
    }
    ptr->id = submessage;
    ptr->extra = extra;
    ptr->next = NULL;
    if (last) {
      last->next = ptr;
    }
    return ptr;
}


/* Free the entire list */
static void sm_counter_free(struct SMCounterRecord *head) {
  struct SMCounterRecord *ptr;
  while (head != NULL) {
    ptr = head->next;
    g_free(head);
    head = ptr;
  }
}



/* *********************************************************************** */
/* Format the given address (16 octects) as an IPv6 address
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


/* *********************************************************************** */
static void rtps_util_add_protocol_version(proto_tree *tree, /* Can NOT be NULL */
                        tvbuff_t *  tvb,
                        gint        offset) {
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
                        ENC_BIG_ENDIAN);
  proto_tree_add_item(version_tree,
                        hf_rtps_protocol_version_minor,
                        tvb,
                        offset+1,
                        1,
                        ENC_BIG_ENDIAN);

}


/* ------------------------------------------------------------------------- */
/* Interpret the next bytes as vendor ID. If proto_tree and field ID is
 * provided, it can also set.
 */
static void rtps_util_add_vendor_id(proto_tree *tree,   /* Can be NULL */
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

    default:
      g_snprintf(vendor_name, MAX_VENDOR_ID_SIZE, "%d.%d", major, minor);
  }

  if (tree != NULL) {
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
static void rtps_util_add_locator_t(proto_tree *tree, /* Can NOT be NULL */
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
 */
static void rtps_util_add_locator_list(proto_tree *tree,
                        tvbuff_t * tvb,
                        gint       offset,
                        const guint8 * label,
                        int        little_endian) {

  proto_item *ti;
  proto_tree *locator_tree;
  guint32 num_locators;

  num_locators = NEXT_guint32(tvb, offset, little_endian);
  ti = proto_tree_add_text(tree,
                        tvb,
                        offset,
                        4,
                        "%s: %d Locators",
                        label,
                        num_locators);

  if (num_locators > 0) {
    guint32 i;
    char temp_buff[20];

    locator_tree = proto_item_add_subtree(ti,
                        ett_rtps_locator_udp_v4);

    for (i = 0; i < num_locators; ++i) {
      g_snprintf(temp_buff, 20, "Locator[%d]", i);
      rtps_util_add_locator_t(locator_tree,
                        tvb,
                        offset + 4 + (i * 24),
                        little_endian,
                        temp_buff,
                        NULL,
                        0);
    }
  }
}


/* ------------------------------------------------------------------------- */
/* Insert in the protocol tree the next 4 bytes interpreted as IPV4Address_t
 */
static void rtps_util_add_ipv4_address_t(proto_tree *tree, /* Can be NULL */
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
static void rtps_util_add_locator_udp_v4(proto_tree *tree, /* Can NOT be NULL */
                        tvbuff_t * tvb,
                        gint       offset,
                        const guint8 * label,
                        int        little_endian) {

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


/* ------------------------------------------------------------------------- */
/* Insert in the protocol tree the next 8 bytes interpreted as GuidPrefix
 * If tree is specified, it fills up the protocol tree item:
 *  - hf_rtps_guid_prefix
 *  - hf_rtps_host_id
 *  - hf_rtps_app_id
 *  - hf_rtps_app_id_instance_id
 *  - hf_rtps_app_id_app_kind
 *
 * If buffer is specified, it returns in it a string representation of the
 * data read.
 */
static void rtps_util_add_guid_prefix(proto_tree *tree, /* Can be NULL */
                        tvbuff_t * tvb,
                        gint       offset,
                        int        hf_prefix,           /* Cannot be 0 if tree != NULL */
                        int        hf_host_id,
                        int        hf_app_id,
                        int        hf_app_id_instance_id,
                        int        hf_app_id_app_kind,
                        const guint8 * label,           /* Can be NULL */
                        guint8 *   buffer,              /* Can be NULL */
                        gint       buffer_size) {
  guint32  host_id;
  guint32  app_id;
  guint32  instance_id;
  guint8   app_kind;
  guint8 * temp_buff;
  guint8   guid_prefix[8];
  const guint8 * safe_label;
  int i;

  safe_label = (label == NULL) ? (const guint8 *)"guidPrefix" : label;

  /* Read values from TVB */
  host_id   = tvb_get_ntohl(tvb, offset);
  app_id    = tvb_get_ntohl(tvb, offset + 4);
  for (i = 0; i < 8; ++i) {
    guid_prefix[i] = tvb_get_guint8(tvb, offset+i);
  }
  instance_id = (app_id >> 8);
  app_kind    = (app_id & 0xff);

  /* Format the string */
  temp_buff = (guint8 *)ep_alloc(MAX_GUID_PREFIX_SIZE);
  g_snprintf(temp_buff, MAX_GUID_PREFIX_SIZE,
                        "%s=%02x%02x%02x%02x %02x%02x%02x%02x"
                        " { hostId=%08x, appId=%08x"
                        " (%s: %06x) }",
                        safe_label,
                        guid_prefix[0],
                        guid_prefix[1],
                        guid_prefix[2],
                        guid_prefix[3],
                        guid_prefix[4],
                        guid_prefix[5],
                        guid_prefix[6],
                        guid_prefix[7],
                        host_id,
                        app_id,
                        val_to_str(app_kind, app_kind_vals, "%02x"),
                        instance_id);

  if (tree != NULL) {
    proto_item * ti, *hidden_item;
    proto_tree * guid_tree;
    proto_tree * appid_tree;

    /* The numeric value (used for searches) */
    hidden_item = proto_tree_add_item(tree,
                        hf_prefix,
                        tvb,
                        offset,
                        8,
                        ENC_NA);
    PROTO_ITEM_SET_HIDDEN(hidden_item);

    /* The text node (root of the guid prefix sub-tree) */
    ti = proto_tree_add_text(tree,
                        tvb,
                        offset,
                        8, "%s",
                        temp_buff);

    guid_tree = proto_item_add_subtree(ti,
                        ett_rtps_guid_prefix);

    /* Host Id */
    proto_tree_add_item(guid_tree,
                        hf_host_id,
                        tvb,
                        offset,
                        4,
                        ENC_BIG_ENDIAN);

    /* AppId (root of the app_id sub-tree */
    ti = proto_tree_add_item(guid_tree,
                        hf_app_id,
                        tvb,
                        offset+4,
                        4,
                        ENC_BIG_ENDIAN);
    appid_tree = proto_item_add_subtree(ti,
                        ett_rtps_app_id);

    /* InstanceId */
    proto_tree_add_item(appid_tree,
                        hf_app_id_instance_id,
                        tvb,
                        offset+4,
                        3,
                        ENC_BIG_ENDIAN);
    /* AppKind */
    proto_tree_add_item(appid_tree,
                        hf_app_id_app_kind,
                        tvb,
                        offset+7,
                        1,
                        ENC_BIG_ENDIAN);
  }

  if (buffer != NULL) {
    g_strlcpy(buffer, temp_buff, buffer_size);
  }
}



/* ------------------------------------------------------------------------- */
 /* Insert the entityId from the next 4 bytes. Since there are more than
  * one entityId, we need to specify also the IDs of the entityId (and its
  * sub-components), as well as the label identifying it.
  * Returns true if the entityKind is one of the NDDS built-in entities.
  */
static int rtps_util_add_entity_id(proto_tree *tree,
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


  if (tree != NULL) {
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
                                        "unknown (%02x)"),
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
                        ENC_BIG_ENDIAN);

    proto_tree_add_item(entity_tree,
                        hf_item_entity_kind,
                        tvb,
                        offset+3,
                        1,
                        ENC_BIG_ENDIAN);

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

  if (tree != NULL) {
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
 /* Interpret the next 12 octets as a generic GUID and insert it in the protocol
  * tree as simple text (no reference fields are set).
  * It is mostly used in situation where is not required to perform search for
  * this kind of GUID (i.e. like in some DATA parameter lists).
  */
static void rtps_util_add_generic_guid(proto_tree *tree,                /* Cannot be NULL */
                        tvbuff_t * tvb,                         /* Cannot be NULL */
                        gint       offset,
                        const char *label,                      /* Cannot be NULL */
                        guint8 *   buffer,                      /* Can be NULL */
                        gint       buffer_size) {

  guint32 host_id;
  guint32 app_id;
  guint8  app_kind;
  guint32 instance_id;
  guint32 entity_id;
  guint32 entity_key;
  guint8  entity_kind;
  guint8  guid_raw[12];
  const char * str_entity_kind;
  const char * str_app_kind;
  guint8 temp_buff[MAX_GUID_SIZE];
  int i;

  /* Read typed data */
  host_id   = tvb_get_ntohl(tvb, offset);
  app_id    = tvb_get_ntohl(tvb, offset + 4);
  entity_id = tvb_get_ntohl(tvb, offset + 8);

  /* Re-Read raw data */
  for (i = 0; i < 12; ++i) {
    guid_raw[i] = tvb_get_guint8(tvb, offset+i);
  }

  /* Split components from typed data */
  instance_id = (app_id >> 8);
  app_kind    = (app_id & 0xff);
  entity_key  = (entity_id >> 8);
  entity_kind = (entity_id & 0xff);

  /* Lookup for predefined app kind and entity kind */
  str_entity_kind = val_to_str(entity_kind, entity_kind_vals, "%02x");
  str_app_kind    = val_to_str(app_kind, app_kind_vals, "%02x");

  /* Compose output buffer for raw guid */
  g_snprintf(temp_buff, MAX_GUID_SIZE,
                        "%s=%02x%02x%02x%02x %02x%02x%02x%02x %02x%02x%02x%02x: "
                        "{ hostId=%08x, appId=%08x (%s: %06x), entityId=%08x (%s: %06x) }",
                        label,
                        guid_raw[0], guid_raw[1], guid_raw[2], guid_raw[3],
                        guid_raw[4], guid_raw[5], guid_raw[6], guid_raw[7],
                        guid_raw[8], guid_raw[9], guid_raw[10], guid_raw[11],
                        host_id,
                        app_id, str_app_kind, instance_id,
                        entity_id, str_entity_kind, entity_key);
  proto_tree_add_text(tree, tvb, offset, 12, "%s", temp_buff);
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

  if (tree != NULL) {
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
static void rtps_util_add_ntp_time(proto_tree *tree,    /* Can be NULL */
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
  if (tree != NULL) {
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
                        little_endian ? ENC_LITTLE_ENDIAN : ENC_BIG_ENDIAN);
  }
  if (buffer != NULL) {
    g_strlcpy(buffer, tempBuffer, buffer_size);
  }
}

/* ------------------------------------------------------------------------- */
/* Insert in the protocol tree the next data interpreted as a String
 * Returns the new offset (after reading the string)
 */
static gint rtps_util_add_string(proto_tree *tree,      /* Can be NULL */
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

  if (tree != NULL) {
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
 */
static void rtps_util_add_long(proto_tree *tree,        /* Can be NULL */
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
                        little_endian ? ENC_LITTLE_ENDIAN : ENC_BIG_ENDIAN);
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
}

/* ------------------------------------------------------------------------- */
/* Insert in the protocol tree the next data interpreted as a port (unsigned
 * 32-bit integer)
 */
static void rtps_util_add_port(proto_tree *tree,        /* Can be NULL */
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
static void rtps_util_add_boolean(proto_tree *tree,     /* Can be NULL */
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

/* ------------------------------------------------------------------------- */
/* Insert in the protocol tree the next bytes interpreted as enum type.
 */
static void rtps_util_add_kind_qos(proto_tree *tree,    /* Can be NULL */
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
static gint rtps_util_add_seq_string(proto_tree *tree,  /* Can NOT be NULL */
                        tvbuff_t * tvb,
                        gint       offset,
                        int        little_endian,
                        int        param_length,
                        char *     label,
                        guint8 *   buffer,              /* Can NOT be NULL */
                        gint       buffer_size) {
  guint32 num_strings;
  guint32 i;
  proto_tree *string_tree;
  proto_item *ti;
  char temp_buff[MAX_LABEL_SIZE];
  guint8 overview_buffer[MAX_LABEL_SIZE];

  num_strings = NEXT_guint32(tvb, offset, little_endian);
  proto_tree_add_text(tree,
                        tvb,
                        offset,
                        4,
                        "size: %d", num_strings);
  offset += 4;

  /* Create the string node with a fake string, the replace it later */
  ti = proto_tree_add_text(tree,
                        tvb,
                        offset,
                        param_length-8,
                        "Strings");
  string_tree = proto_item_add_subtree(ti, ett_rtps_seq_string);

  overview_buffer[0] = '\0';

  for (i = 0; i < num_strings; ++i) {
    g_snprintf(temp_buff, MAX_LABEL_SIZE,
                        "%s[%d]",
                        label,
                        i);
    offset = rtps_util_add_string(string_tree,
                        tvb,
                        offset,
                        -1,
                        little_endian,
                        temp_buff,
                        overview_buffer+strlen(overview_buffer),
                        MAX_LABEL_SIZE-strlen(overview_buffer));
  }
  proto_item_set_text(ti,
                        "%s: %s",
                        label,
                        overview_buffer);
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
static gint rtps_util_add_seq_ulong(proto_tree *tree,   /* Can NOT be NULL */
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
  ti = proto_tree_add_text(tree,
                        tvb,
                        offset,
                        param_length-8,
                        "Seq");
  string_tree = proto_item_add_subtree(ti, ett_rtps_seq_ulong);

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
                        int        seq_max_len, /* -1 = not a sequence field */
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
                    -1,
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
        } else {
          typecode_name = "struct";
        }

        if (seq_max_len != -1) {
          /* We're dissecting a sequence of struct, bypass the seq definition */
          g_snprintf(type_name, 40, "%s", struct_name);
          break;
        }
        /* Prints it */
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
                          -1,
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
                          -1,
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
        value_name = tvb_get_ephemeral_string(tvb, offset, value_name_len);
        offset += value_name_len;

        g_snprintf(type_name, 40, "valuetype %s", value_name);
        break;
    }
  } /* switch(tk_id) */

  /* Sequence print */
  if (seq_max_len != -1) {
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
    emem_strbuf_t *dim_str = ep_strbuf_new_label(NULL);
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
 * Octects.
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
    g_strlcpy(buffer,
                        "RTPS PROTOCOL ERROR: parameter value too small",
                        buffer_size);
    proto_tree_add_text(tree,
                      tvb,
                      offset,
                      param_length, "%s",
                      buffer);
    return ;
  }

  /* Limit the number of octects displayed to MAX_SEQ_OCTETS_PRINTED */
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

  if (tree != NULL) {
    proto_tree_add_text(tree,
                        tvb,
                        original_offset,
                        4,
                        "sequenceSize: %d octects",
                        original_seq_length);
    proto_tree_add_item(tree,
                        hf_id,
                        tvb,
                        original_offset+4,
                        original_seq_length,
                        little_endian ? ENC_LITTLE_ENDIAN : ENC_BIG_ENDIAN);

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
  for (i = 0; i < num_bits; i += 32) {
    data = NEXT_guint32(tvb, offset, little_endian);
    offset += 4;
    for (j = 0; j < 32; ++j) {
      datamask = (1 << (31-j));
      temp_buff[idx] = ((data & datamask) == datamask) ? '1':'0';
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

  /* removes all the ending '0' */
  for (i = (int) strlen(temp_buff) - 1; (i>0 && temp_buff[i] == '0'); --i) {
      temp_buff[i] = '\0';
  }

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
  return offset;
}


/* ------------------------------------------------------------------------- */
/* Decode the submessage flags
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
#define ENSURE_LENGTH(size)                                             \
        if (param_length < size) {                                      \
          proto_tree_add_text(rtps_parameter_tree,                      \
                        tvb, offset, param_length,                      \
                        "RTPS PROTOCOL ERROR: parameter value too small"\
                        " (must be at least %d octects)", size);        \
          break;                                                        \
        }

static gint dissect_parameter_sequence(proto_tree *tree,
                        tvbuff_t *tvb,
                        gint offset,
                        int  little_endian,
                        int octects_to_next_header,
                        const char * label) {
  proto_item * ti;
  proto_tree * rtps_parameter_sequence_tree;
  proto_tree * rtps_parameter_tree;
  guint16      parameter, param_length;
  guint8       buffer[MAX_PARAM_SIZE];
  gint         max_param_section = offset + octects_to_next_header;

  buffer[0] = '\0';

  ti = proto_tree_add_text(tree,
                        tvb,
                        offset,
                        -1,
                        "%s:", label);
  rtps_parameter_sequence_tree = proto_item_add_subtree(ti,
                        ett_rtps_parameter_sequence);


  /* Loop through all the parameters defined until PID_SENTINEL is found */
  do {
    if (max_param_section-offset < 4) {
      proto_tree_add_text(tree,
                        tvb,
                        offset,
                        1,
                        "RTPS PROTOCOL ERROR: not enough bytes to read "
                                                " the next parameter");
      return 0;
    }

    /* Reads parameter and create the sub tree. At this point we don't know
     * the final string that will identify the node or its length. It will
     * be set later...
     */
    parameter = NEXT_guint16(tvb, offset, little_endian);
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

    offset += 2;

    /* parameter length */
    param_length = NEXT_guint16(tvb, offset, little_endian);
    proto_tree_add_item(rtps_parameter_tree,
                        hf_rtps_parameter_length,
                        tvb,
                        offset,
                        2,
                        little_endian ? ENC_LITTLE_ENDIAN : ENC_BIG_ENDIAN);
    offset += 2;

    /* Make sure we have enough bytes for the param value */
    if ((max_param_section-offset < param_length) &&
        (parameter != PID_SENTINEL)) {
      proto_tree_add_text(tree,
                        tvb,
                        offset,
                        1,
                        "RTPS PROTOCOL ERROR: not enough bytes to read "
                                                " the parameter value");
      return 0;
    }

    /* Sets the end of this item (now we know it!) */
    proto_item_set_len(ti, param_length+4);

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
       * | PID_DEFAULT_EXPECTS_INLINE_QOS|            0x0004             |
       * +---------------+---------------+---------------+---------------+
       * |    boolean    |       N O T      U S E D                      |
       * +---------------+---------------+---------------+---------------+
       */
      case PID_DEFAULT_EXPECTS_INLINE_QOS:
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

        /* Older version of the protocol (and for PID_RELIABILITY_OFFERED)
         * this parameter was carrying also a NtpTime called
         * 'maxBlockingTime'.
         */
        if (octects_to_next_header == 12) {
          rtps_util_add_ntp_time(rtps_parameter_tree,
                        tvb,
                        offset + 4,
                        little_endian,
                        "maxBlockingTime",
                        NULL,
                        0);
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
       * |   octect[0]   |   octet[1]    |   octect[2]   |   octet[3]    |
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
       * |   octect[0]   |   octet[1]    |   octect[2]   |   octet[3]    |
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
       * |   octect[0]   |   octet[1]    |   octect[2]   |   octet[3]    |
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
        ENSURE_LENGTH(12);
        rtps_util_add_generic_guid(rtps_parameter_tree,
                        tvb,
                        offset,
                        "Participant GUID",
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
        ENSURE_LENGTH(12);
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
                        MAX_PARAM_SIZE-(gulong) strlen(buffer),
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
        g_strlcpy(buffer, "[DEPRECATED] - Parameter not decoded", MAX_PARAM_SIZE);

      case PID_PAD:
      case PID_RELIABILITY_ENABLED:
      default:
        if (param_length > 0) {
          proto_tree_add_text(rtps_parameter_tree,
                        tvb,
                        offset,
                        param_length,
                        "parameterData");
        }
    } /* End switch */

    if (buffer[0]) {
      proto_item_append_text(ti, ": %s", buffer);
      buffer[0] = '\0';
    }
    offset += param_length;

  } while(parameter != PID_SENTINEL); /* for all the parameters */
  return offset;
}
#undef ENSURE_LENGTH




/* *********************************************************************** */
/* *                                 P A D                               * */
/* *********************************************************************** */
static void dissect_PAD(tvbuff_t *tvb,
                gint offset,
                guint8 flags,
                gboolean little_endian,
                int octects_to_next_header,
                proto_tree *tree) {
  /* 0...2...........7...............15.............23...............31
   * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   * |   PAD         |X|X|X|X|X|X|X|E|      octetsToNextHeader       |
   * +---------------+---------------+---------------+---------------+
   */
  rtps_util_decode_flags(tree, tvb, offset + 1, flags, PAD_FLAGS);

  if (octects_to_next_header != 0) {
    proto_tree_add_uint_format(tree,
                        hf_rtps_sm_octets_to_next_header,
                        tvb,
                        offset + 2,
                        2,
                        octects_to_next_header,
                        "octectsToNextHeader: %u (Error: should be ZERO)",
                        octects_to_next_header);
    return;
  }

  proto_tree_add_item(tree,
                        hf_rtps_sm_octets_to_next_header,
                        tvb,
                        offset + 2,
                        2,
                        little_endian ? ENC_LITTLE_ENDIAN : ENC_BIG_ENDIAN);
}





/* *********************************************************************** */
/* *                               D A T A                               * */
/* *********************************************************************** */
static void dissect_DATA(tvbuff_t *tvb,
                gint offset,
                guint8 flags,
                gboolean little_endian,
                int octects_to_next_header,
                proto_tree *tree,
                const char ** sm_data) {        /* May be set to some known values */
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
  rtps_util_decode_flags(tree, tvb, offset + 1, flags, DATA_FLAGS);


  /* Calculates the minimum length for this submessage */
  min_len = 20;
  if ((flags & FLAG_DATA_H) != 0) min_len += 8;
  if ((flags & FLAG_DATA_Q) != 0) min_len += 4;
  if ((flags & FLAG_DATA_D) != 0) min_len += 4;

  if (octects_to_next_header < min_len) {
    proto_tree_add_uint_format(tree,
                        hf_rtps_sm_octets_to_next_header,
                        tvb,
                        offset+2,
                        2,
                        octects_to_next_header,
                        "octectsToNextHeader: %u (Error: should be >= %u)",
                        octects_to_next_header,
                        min_len);
    return;
  }
  proto_tree_add_item(tree,
                        hf_rtps_sm_octets_to_next_header,
                        tvb,
                        offset + 2,
                        2,
                        little_endian ? ENC_LITTLE_ENDIAN : ENC_BIG_ENDIAN);
  offset += 4;


  /* readerEntityId */
  is_builtin_entity |= rtps_util_add_entity_id(tree,
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
  is_builtin_entity |= rtps_util_add_entity_id(tree,
                        tvb,
                        offset,
                        hf_rtps_sm_wrentity_id,
                        hf_rtps_sm_wrentity_id_key,
                        hf_rtps_sm_wrentity_id_kind,
                        ett_rtps_wrentity,
                        "writerEntityId",
                        &wid);
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
        *sm_data = SM_EXTRA_WPLUS;
  } else if (wid == ENTITYID_BUILTIN_PUBLICATIONS_WRITER && (flags & FLAG_DATA_A) == 0) {
        *sm_data = SM_EXTRA_WMINUS;
  } else if (wid == ENTITYID_BUILTIN_SUBSCRIPTIONS_WRITER && (flags & FLAG_DATA_A) != 0) {
        *sm_data = SM_EXTRA_RPLUS;
  } else if (wid == ENTITYID_BUILTIN_SUBSCRIPTIONS_WRITER && (flags & FLAG_DATA_A) == 0) {
        *sm_data = SM_EXTRA_RMINUS;
  } else if (wid == ENTITYID_BUILTIN_SDP_PARTICIPANT_WRITER && (flags & FLAG_DATA_A) != 0) {
        *sm_data = SM_EXTRA_PPLUS;
  } else if (wid == ENTITYID_BUILTIN_SDP_PARTICIPANT_WRITER && (flags & FLAG_DATA_A) == 0) {
        *sm_data = SM_EXTRA_PMINUS;
  } else if (wid == ENTITYID_BUILTIN_TOPIC_WRITER && (flags & FLAG_DATA_A) != 0) {
        *sm_data = SM_EXTRA_TPLUS;
  } else if (wid == ENTITYID_BUILTIN_TOPIC_WRITER && (flags & FLAG_DATA_A) == 0) {
        *sm_data = SM_EXTRA_TMINUS;
  }

  /* If flag H is defined, read the HostId and AppId fields */
  if ((flags & FLAG_DATA_H) != 0) {
    rtps_util_add_guid_prefix(tree,
                        tvb,
                        offset,
                        hf_rtps_sm_guid_prefix,
                        hf_rtps_sm_host_id,
                        hf_rtps_sm_app_id,
                        hf_rtps_sm_instance_id,
                        hf_rtps_sm_app_kind,
                        "keyHashPrefix",
                        NULL,
                        0);

    offset += 8;
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
                        octects_to_next_header,
                        "inlineQos");
  }

  /* SerializedData */
  if ((flags & FLAG_DATA_D) != 0) {
    if (is_builtin_entity) {
      offset = dissect_parameter_sequence(tree,
                        tvb,
                        offset,
                        little_endian,
                        octects_to_next_header,
                        "serializedData");
    } else {
      proto_tree_add_item(tree,
                        hf_rtps_issue_data,
                        tvb,
                        offset,
                        octects_to_next_header - (offset - old_offset) + 4,
                        little_endian ? ENC_LITTLE_ENDIAN : ENC_BIG_ENDIAN);
    }
  }
}

/* *********************************************************************** */
/* *                        N O K E Y _ D A T A                          * */
/* *********************************************************************** */
static void dissect_NOKEY_DATA(tvbuff_t *tvb,
                gint offset,
                guint8 flags,
                gboolean little_endian,
                int octects_to_next_header,
                proto_tree *tree) {
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
   * Notes:
   *   - inlineQos is equivalent to the old 'parameters'
   *   - serializedData is equivalent to the old 'issueData'
   */

  int  min_len;
  gint old_offset = offset;
  rtps_util_decode_flags(tree, tvb, offset + 1, flags, NOKEY_DATA_FLAGS);


  /* Calculates the minimum length for this submessage */
  min_len = 16;
  if ((flags & FLAG_NOKEY_DATA_Q) != 0) min_len += 4;

  if (octects_to_next_header < min_len) {
    proto_tree_add_uint_format(tree,
                        hf_rtps_sm_octets_to_next_header,
                        tvb,
                        offset+2,
                        2,
                        octects_to_next_header,
                        "octectsToNextHeader: %u (Error: should be >= %u)",
                        octects_to_next_header,
                        min_len);
    return;
  }
  proto_tree_add_item(tree,
                        hf_rtps_sm_octets_to_next_header,
                        tvb,
                        offset + 2,
                        2,
                        little_endian ? ENC_LITTLE_ENDIAN : ENC_BIG_ENDIAN);
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

  /* Parameters */
  if ((flags & FLAG_NOKEY_DATA_Q) != 0) {
    offset = dissect_parameter_sequence(tree,
                        tvb,
                        offset,
                        little_endian,
                        octects_to_next_header,
                        "inlineQos");

  }

  /* Issue Data */
  if ((flags & FLAG_NOKEY_DATA_D) == 0) {
    proto_tree_add_item(tree,
                        hf_rtps_issue_data,
                        tvb,
                        offset,
                        octects_to_next_header - (offset - old_offset) + 4,
                        little_endian ? ENC_LITTLE_ENDIAN : ENC_BIG_ENDIAN);
  }
}


/* *********************************************************************** */
/* *                            A C K N A C K                            * */
/* *********************************************************************** */
static void dissect_ACKNACK(tvbuff_t *tvb,
                gint offset,
                guint8 flags,
                gboolean little_endian,
                int octects_to_next_header,
                proto_tree *tree) {
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
   * RTPS 1.2:
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

  if (octects_to_next_header < 20) {
    proto_tree_add_uint_format(tree,
                        hf_rtps_sm_octets_to_next_header,
                        tvb,
                        offset + 2,
                        2,
                        octects_to_next_header,
                        "octectsToNextHeader: %u (Error: should be >= 20)",
                        octects_to_next_header);
    return;
  }
  proto_tree_add_item(tree,
                        hf_rtps_sm_octets_to_next_header,
                        tvb,
                        offset + 2,
                        2,
                        little_endian ? ENC_LITTLE_ENDIAN : ENC_BIG_ENDIAN);
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
  if (offset + 4 == original_offset + octects_to_next_header) {
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
  } else if (offset < original_offset + octects_to_next_header) {
    /* In this case there must be something wrong in the bitmap: there
     * are some extra bytes that we don't know how to decode
     */
    proto_tree_add_text(tree,
                        tvb,
                        offset,
                        octects_to_next_header - offset,
                        "Packet malformed: don't know how to decode those "
                        "extra bytes: %d",
                        octects_to_next_header - offset);
  } else if (offset > original_offset + octects_to_next_header) {
    /* Decoding the bitmap went over the end of this submessage.
     * Enter an item in the protocol tree that spans over the entire
     * submessage.
     */
    proto_tree_add_text(tree,
                        tvb,
                        original_offset,
                        octects_to_next_header + original_offset,
                        "Packet malformed: not enough bytes to decode");
  }

}



/* *********************************************************************** */
/* *                           H E A R T B E A T                         * */
/* *********************************************************************** */
static void dissect_HEARTBEAT(tvbuff_t *tvb,
                gint offset,
                guint8 flags,
                gboolean little_endian,
                int octects_to_next_header,
                proto_tree *tree) {
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
   * RTPS 1.2:
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
  rtps_util_decode_flags(tree, tvb, offset + 1, flags, HEARTBEAT_FLAGS);


  if (octects_to_next_header < 24) {
    proto_tree_add_uint_format(tree,
                        hf_rtps_sm_octets_to_next_header,
                        tvb,
                        offset+2,
                        2,
                        octects_to_next_header,
                        "octectsToNextHeader: %u (Error: should be >= 24)",
                        octects_to_next_header);
    return;
  }
  proto_tree_add_item(tree,
                        hf_rtps_sm_octets_to_next_header,
                        tvb,
                        offset + 2,
                        2,
                        little_endian ? ENC_LITTLE_ENDIAN : ENC_BIG_ENDIAN);
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
                        "firstAvailableSeqNumber");
  offset += 8;

  /* Last Sequence Number */
  rtps_util_add_seq_number(tree,
                        tvb,
                        offset,
                        little_endian,
                        "lastSeqNumber");
  offset += 8;

  /* Counter: it was not present in RTPS 1.0 */
  if (octects_to_next_header == 0x28) {
    counter = NEXT_guint32(tvb, offset, little_endian);
    proto_tree_add_text(tree,
                        tvb,
                        offset,
                        4,
                        "count: %u",
                        counter);
  }
}


/* *********************************************************************** */
/* *                                 G A P                               * */
/* *********************************************************************** */
static void dissect_GAP(tvbuff_t *tvb,
                gint offset,
                guint8 flags,
                gboolean little_endian,
                int octects_to_next_header,
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

  rtps_util_decode_flags(tree, tvb, offset + 1, flags, GAP_FLAGS);

  if (octects_to_next_header < 24) {
    proto_tree_add_uint_format(tree,
                        hf_rtps_sm_octets_to_next_header,
                        tvb,
                        offset + 2,
                        2,
                        octects_to_next_header,
                        "octectsToNextHeader: %u (Error: should be >= 24)",
                        octects_to_next_header);
    return;
  }
  proto_tree_add_item(tree,
                        hf_rtps_sm_octets_to_next_header,
                        tvb,
                        offset + 2,
                        2,
                        little_endian ? ENC_LITTLE_ENDIAN : ENC_BIG_ENDIAN);
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
}


/* *********************************************************************** */
/* *                           I N F O _ T S                             * */
/* *********************************************************************** */
static void dissect_INFO_TS(tvbuff_t *tvb,
                gint offset,
                guint8 flags,
                gboolean little_endian,
                int octects_to_next_header,
                proto_tree *tree) {
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
   * RTPS 1.2:
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
  rtps_util_decode_flags(tree, tvb, offset + 1, flags, INFO_TS_FLAGS);

  min_len = 0;
  if ((flags & FLAG_INFO_TS_T) == 0) min_len += 8;

  if (octects_to_next_header != min_len) {
    proto_tree_add_uint_format(tree,
                        hf_rtps_sm_octets_to_next_header,
                        tvb,
                        offset+2,
                        2,
                        octects_to_next_header,
                        "octectsToNextHeader: %u (Error: should be == %u)",
                        octects_to_next_header,
                        min_len);
    return;
  }

  proto_tree_add_item(tree,
                        hf_rtps_sm_octets_to_next_header,
                        tvb,
                        offset + 2,
                        2,
                        little_endian ? ENC_LITTLE_ENDIAN : ENC_BIG_ENDIAN);
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
}


/* *********************************************************************** */
/* *                           I N F O _ S R C                           * */
/* *********************************************************************** */
static void dissect_INFO_SRC(tvbuff_t *tvb,
                gint offset,
                guint8 flags,
                gboolean little_endian,
                int octects_to_next_header,
                proto_tree *tree) {
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
   * RTPS 1.2:
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

  rtps_util_decode_flags(tree, tvb, offset + 1, flags, INFO_SRC_FLAGS);

  if (octects_to_next_header != 16) {
    proto_tree_add_uint_format(tree,
                        hf_rtps_sm_octets_to_next_header,
                        tvb,
                        offset+2,
                        2,
                        octects_to_next_header,
                        "octectsToNextHeader: %u (Error: should be == 16)",
                        octects_to_next_header);
    return;
  }

  proto_tree_add_item(tree,
                        hf_rtps_sm_octets_to_next_header,
                        tvb,
                        offset + 2,
                        2,
                        little_endian ? ENC_LITTLE_ENDIAN : ENC_BIG_ENDIAN);
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
                        hf_rtps_sm_instance_id,
                        hf_rtps_sm_app_kind,
                        NULL,   /* Use default 'guidPrefix' */
                        NULL,
                        0);
#if 0
    rtps_util_add_guid_prefix(tree,
                        tvb,
                        offset,
                        hf_rtps_sm_guid_prefix,
                        hf_rtps_sm_host_id,
                        hf_rtps_sm_app_id,
                        hf_rtps_sm_instance_id,
                        hf_rtps_sm_app_kind,
                        NULL,   /* Use default 'guidPrefix' */
                        &temp_buffer[0],
                        MAX_GUID_PREFIX_SIZE);
    proto_tree_add_text(tree,
                        tvb,
                        offset,
                        8,
                        temp_buffer);
#endif
  }

}


/* *********************************************************************** */
/* *                    I N F O _ R E P L Y _ I P 4                      * */
/* *********************************************************************** */
static void dissect_INFO_REPLY_IP4(tvbuff_t *tvb,
                gint offset,
                guint8 flags,
                gboolean little_endian,
                int octects_to_next_header,
                proto_tree *tree) {
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
   * RTPS 1.2:
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


  if (octects_to_next_header != min_len) {
    proto_tree_add_uint_format(tree,
                        hf_rtps_sm_octets_to_next_header,
                        tvb,
                        offset+2,
                        2,
                        octects_to_next_header,
                        "octectsToNextHeader: %u (Error: should be == %u)",
                        octects_to_next_header,
                        min_len);
    return;
  }

  proto_tree_add_item(tree,
                        hf_rtps_sm_octets_to_next_header,
                        tvb,
                        offset + 2,
                        2,
                        little_endian ? ENC_LITTLE_ENDIAN : ENC_BIG_ENDIAN);
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
}

/* *********************************************************************** */
/* *                           I N F O _ D S T                           * */
/* *********************************************************************** */
static void dissect_INFO_DST(tvbuff_t *tvb,
                gint offset,
                guint8 flags,
                gboolean little_endian,
                int octects_to_next_header,
                proto_tree *tree) {
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
   * RTPS 1.2:
   * 0...2...........7...............15.............23...............31
   * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   * |   INFO_DST    |X|X|X|X|X|X|X|E|      octetsToNextHeader       |
   * +---------------+---------------+---------------+---------------+
   * |                                                               |
   * + GuidPrefix guidPrefix                                         +
   * |                                                               |
   * +---------------+---------------+---------------+---------------+
   */

  rtps_util_decode_flags(tree, tvb, offset + 1, flags, INFO_DST_FLAGS);

  if (octects_to_next_header != 8) {
    proto_tree_add_uint_format(tree,
                        hf_rtps_sm_octets_to_next_header,
                        tvb,
                        offset+2,
                        2,
                        octects_to_next_header,
                        "octectsToNextHeader: %u (Error: should be == 8)",
                        octects_to_next_header);
    return;
  }

  proto_tree_add_item(tree,
                        hf_rtps_sm_octets_to_next_header,
                        tvb,
                        offset + 2,
                        2,
                        little_endian ? ENC_LITTLE_ENDIAN : ENC_BIG_ENDIAN);
  offset += 4;

  {
    rtps_util_add_guid_prefix(tree,
                        tvb,
                        offset,
                        hf_rtps_sm_guid_prefix,
                        hf_rtps_sm_host_id,
                        hf_rtps_sm_app_id,
                        hf_rtps_sm_instance_id,
                        hf_rtps_sm_app_kind,
                        NULL,
                        NULL,
                        0);
  }
}



/* *********************************************************************** */
/* *                        I N F O _ R E P L Y                          * */
/* *********************************************************************** */
static void dissect_INFO_REPLY(tvbuff_t *tvb,
                gint offset,
                guint8 flags,
                gboolean little_endian,
                int octects_to_next_header,
                proto_tree *tree) {
  /* RTPS 1.0/1.1:
   *   INFO_REPLY is *NOT* the same thing as the old INFO_REPLY.
   *
   * RTPS 1.2:
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


  if (octects_to_next_header != min_len) {
    proto_tree_add_uint_format(tree,
                        hf_rtps_sm_octets_to_next_header,
                        tvb,
                        offset+2,
                        2,
                        octects_to_next_header,
                        "octectsToNextHeader: %u (Error: should be == %u)",
                        octects_to_next_header,
                        min_len);
    return;
  }

  proto_tree_add_item(tree,
                        hf_rtps_sm_octets_to_next_header,
                        tvb,
                        offset + 2,
                        2,
                        little_endian ? ENC_LITTLE_ENDIAN : ENC_BIG_ENDIAN);
  offset += 4;


  /* unicastReplyLocatorList */
  rtps_util_add_locator_list(tree,
                        tvb,
                        offset,
                        "unicastReplyLocatorList",
                        little_endian);

  offset += 8;

  /* multicastReplyLocatorList */
  if ((flags & FLAG_INFO_REPLY_M) != 0) {
    rtps_util_add_locator_list(tree,
                        tvb,
                        offset,
                        "multicastReplyLocatorList",
                        little_endian);
    offset += 8;
  }
}





/***************************************************************************/
/* The main packet dissector function
 */
static gboolean dissect_rtps(tvbuff_t *tvb,
                        packet_info *pinfo,
                        proto_tree *tree) {
  proto_item       *ti = NULL;
  proto_tree       *rtps_tree=NULL;
  gint             offset = 0;
  proto_tree       *rtps_submessage_tree;
  guint8           submessageId;
  guint8           flags;
  gboolean         little_endian;
  gboolean         is_ping = FALSE;
  gint             next_submsg, octects_to_next_header;
  struct SMCounterRecord *smcr_head = NULL;
  struct SMCounterRecord *smcr_last = NULL;
  const gboolean is_tcp = (pinfo->ptype == PT_TCP);
  const char *     sm_extra = NULL;

  if (is_tcp) {
    /* In RTPS over TCP the first 4 bytes are the packet length
     * as 32-bit unsigned int coded as BIG ENDIAN
    guint32 tcp_len  = tvb_get_ntohl(tvb, offset);
     */
    offset = 4;
  }

  /* Check 'RTPS' signature:
   * A header is invalid if it has less than 16 octets
   */
  if (!tvb_bytes_exist(tvb, offset, 16)) return FALSE;
  if (tvb_get_guint8(tvb,offset) != 'R') return FALSE;
  if (tvb_get_guint8(tvb,offset+1) != 'T') return FALSE;
  if (tvb_get_guint8(tvb,offset+2) != 'P') return FALSE;
  if (tvb_get_guint8(tvb,offset+3) != 'S') return FALSE;
  /* Distinguish between RTPS 1.x and 2.x here */
  if (tvb_get_guint8(tvb,offset+4) != 1) return FALSE;

  /* --- Make entries in Protocol column ---*/
  col_set_str(pinfo->cinfo, COL_PROTOCOL, "RTPS");

  col_clear(pinfo->cinfo, COL_INFO);


  if (tree) {
    guint8 nddsPing[8];
    /* create display subtree for the protocol */
    ti = proto_tree_add_item(tree, proto_rtps, tvb, 0, -1, ENC_NA);
    rtps_tree = proto_item_add_subtree(ti, ett_rtps);

    /*  Protocol Version */
    rtps_util_add_protocol_version(rtps_tree, tvb, offset+4);

    /*  Vendor Id  */
    rtps_util_add_vendor_id(rtps_tree, tvb, offset+6, NULL, 0);

    tvb_memcpy(tvb, nddsPing, offset+8, 8);
    if (nddsPing[0] == 'N' &&
        nddsPing[1] == 'D' &&
        nddsPing[2] == 'D' &&
        nddsPing[3] == 'S' &&
        nddsPing[4] == 'P' &&
        nddsPing[5] == 'I' &&
        nddsPing[6] == 'N' &&
        nddsPing[7] == 'G') {
      is_ping = TRUE;
    }

    if (!is_ping) {
      rtps_util_add_guid_prefix(rtps_tree,
                        tvb,
                        offset+8,
                        hf_rtps_guid_prefix,
                        hf_rtps_host_id,
                        hf_rtps_app_id,
                        hf_rtps_app_id_instance_id,
                        hf_rtps_app_id_app_kind,
                        NULL,
                        NULL,
                        0);
    }
  }

  /* Extract the domain id and participant index */
  {
    int domain_id;
    int participant_idx;
    int nature;
    proto_item *ti2;
    proto_tree *mapping_tree;

    domain_id = ((pinfo->destport - PORT_BASE)/10) % 100;
    participant_idx = (pinfo->destport - PORT_BASE) / 1000;
    nature    = (pinfo->destport % 10);

    ti2 = proto_tree_add_text(rtps_tree,
                        tvb,
                        0,
                        4,
                        "Default port mapping: domainId=%d, "
                        "participantIdx=%d, nature=%s",
                        domain_id,
                        participant_idx,
                        val_to_str(nature, nature_type_vals, "%02x"));

    mapping_tree = proto_item_add_subtree(ti2, ett_rtps_default_mapping);
    proto_tree_add_uint(mapping_tree,
                        hf_rtps_domain_id,
                        tvb,
                        0,
                        4,
                        domain_id);
    proto_tree_add_uint(mapping_tree,
                        hf_rtps_participant_idx,
                        tvb,
                        0,
                        4,
                        participant_idx);
    proto_tree_add_uint(mapping_tree,
                        hf_rtps_nature_type,
                        tvb,
                        0,
                        4,
                        nature);

  }

  /* offset behind RTPS's Header (need to be set in case tree=NULL)*/
  offset=16;

  while (tvb_reported_length_remaining(tvb, offset) > 0) {
    sm_extra = NULL;
    submessageId = tvb_get_guint8(tvb, offset);

    /* Creates the subtree 'Submessage: XXXX' */
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

    /* Gets the flags */
    flags = tvb_get_guint8(tvb, offset + 1);

    /* Gets the E (Little endian) flag */
    little_endian = ((flags & FLAG_E) != 0);

    /* Octect-to-next-header */
    octects_to_next_header  = NEXT_guint16(tvb, offset + 2, little_endian);
    next_submsg = offset + octects_to_next_header + 4;

    /* Set length of this item */
    proto_item_set_len(ti, octects_to_next_header + 4);

    /* Now decode each single submessage */
    /* Note: if tree==NULL, we don't care about the details, so each
     *       sub-message dissector is not invoked. We still need to go
     *       through this switch to count the number of each submessage IDs
     * The offset passed to the dissectors points to the start of the
     * submessage (at the ID byte).
     */
    switch (submessageId)
    {
      case PAD:
        if (tree) {
          dissect_PAD(tvb,
                        offset,
                        flags,
                        little_endian,
                        octects_to_next_header,
                        rtps_submessage_tree);
        }
        break;

      case DATA:
        if (tree) {
          dissect_DATA(tvb,
                        offset,
                        flags,
                        little_endian,
                        octects_to_next_header,
                        rtps_submessage_tree,
                        &sm_extra);
        }
        break;

      case NOKEY_DATA:
        if (tree) {
          dissect_NOKEY_DATA(tvb,
                        offset,
                        flags,
                        little_endian,
                        octects_to_next_header,
                        rtps_submessage_tree);
        }
        break;

      case ACKNACK:
        if (tree) {
          dissect_ACKNACK(tvb,
                        offset,
                        flags,
                        little_endian,
                        octects_to_next_header,
                        rtps_submessage_tree);
        }
        break;

      case HEARTBEAT:
        if (tree) {
          dissect_HEARTBEAT(tvb,
                        offset,
                        flags,
                        little_endian,
                        octects_to_next_header,
                        rtps_submessage_tree);
        }
        break;

      case GAP:
        if (tree) {
          dissect_GAP(tvb,
                        offset,
                        flags,
                        little_endian,
                        octects_to_next_header,
                        rtps_submessage_tree);
        }
        break;

      case INFO_TS:
        if (tree) {
          dissect_INFO_TS(tvb,
                        offset,
                        flags,
                        little_endian,
                        octects_to_next_header,
                        rtps_submessage_tree);
        }
        break;

      case INFO_SRC:
        if (tree) {
          dissect_INFO_SRC(tvb,
                        offset,
                        flags,
                        little_endian,
                        octects_to_next_header,
                        rtps_submessage_tree);
        }
        break;

      case INFO_REPLY_IP4:
        if (tree) {
          dissect_INFO_REPLY_IP4(tvb,
                        offset,
                        flags,
                        little_endian,
                        octects_to_next_header,
                        rtps_submessage_tree);
        }
        break;

      case INFO_DST:
        if (tree) {
          dissect_INFO_DST(tvb,
                        offset,
                        flags,
                        little_endian,
                        octects_to_next_header,
                        rtps_submessage_tree);
        }
        break;

      case INFO_REPLY:
        if (tree) {
          dissect_INFO_REPLY(tvb,
                        offset,
                        flags,
                        little_endian,
                        octects_to_next_header,
                        rtps_submessage_tree);
        }
        break;

      default:
        if (tree) {
          proto_tree_add_uint(rtps_submessage_tree, hf_rtps_sm_flags,
                              tvb, offset + 1, 1, flags);
          proto_tree_add_uint(rtps_submessage_tree,
                                hf_rtps_sm_octets_to_next_header,
                                tvb, offset + 2, 2, next_submsg);
        }
        break;
     }

    /* Record the submessage type in the counter record list */
    smcr_last = sm_counter_add(smcr_last, submessageId, sm_extra);
    if (smcr_head == NULL) {
      smcr_head = smcr_last;
    }

     /* next submessage's offset */
     offset = next_submsg;
  }

  /* Compose the content of the 'summary' column */
  if (check_col(pinfo->cinfo, COL_INFO)) {
    emem_strbuf_t *info_buf = ep_strbuf_new_label(NULL);
    struct SMCounterRecord *smcr_ptr = smcr_head;


    if (is_ping) {
        ep_strbuf_append(info_buf, "PING");
    } else {
      /* Counts of submessages - for Information Frame */
      while (smcr_ptr != NULL) {
        if (info_buf->len > 0) {
          ep_strbuf_append(info_buf, ", ");
        }
        ep_strbuf_append_printf(info_buf, "%s%s",
                                val_to_str(smcr_ptr->id,
                                           submessage_id_vals,
                                           "Unknown[%02x]"),
                                smcr_ptr->extra ? smcr_ptr->extra : "");
        smcr_ptr = smcr_ptr->next;
      }
    }
    col_add_str(pinfo->cinfo, COL_INFO, info_buf->str);
  }
  sm_counter_free(smcr_head);

  /* If TCP there's an extra OOB byte at the end of the message */
  /* TODO: What to do with it? */
  return TRUE;

}  /* dissect_rtps(...) */





/***************************************************************************
 * Register the protocol with Wireshark
 * ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
 */
void proto_register_rtps(void) {

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
        "rtps.version",
        FT_NONE,
        BASE_NONE,
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

    /* Submessage flags ---------------------------------------------------- */
    { &hf_rtps_sm_flags, {
        "flags",
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
        FT_BYTES,
        BASE_NONE,
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

    /* Parameter / NtpTime ------------------------------------------------- */
    { &hf_rtps_param_ntpt, {
        "ntpTime",
        "rtps.param.ntpTime",
        FT_NONE,
        BASE_NONE,
        NULL,
        0,
        "Time using the NTP standard format",
        HFILL }
    },
    { &hf_rtps_param_ntpt_sec, {
        "seconds",
        "rtps.param.ntpTime.sec",
        FT_INT32,
        BASE_DEC,
        NULL,
        0,
        "The 'second' component of a NTP time",
        HFILL }
    },
    { &hf_rtps_param_ntpt_fraction, {
        "fraction",
        "rtps.param.ntpTime.fraction",
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
  };

  proto_rtps = proto_register_protocol(
                        "Real-Time Publish-Subscribe Wire Protocol",
                        "RTPS",
                        "rtps");
  proto_register_field_array(proto_rtps, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));
}


void proto_reg_handoff_rtps(void) {
 heur_dissector_add("udp", dissect_rtps, proto_rtps);
 heur_dissector_add("tcp", dissect_rtps, proto_rtps);
}

