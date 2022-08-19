/* packet-rtps.c
 * ~~~~~~~~~~~~~
 *
 * Routines for Real-Time Publish-Subscribe Protocol (RTPS) dissection
 *
 * (c) 2005-2014 Copyright, Real-Time Innovations, Inc.
 * Real-Time Innovations, Inc.
 * 232 East Java Drive
 * Sunnyvale, CA 94089
 *
 * Copyright 2003, LUKAS POKORNY <maskis@seznam.cz>
 *                 PETR SMOLIK   <petr.smolik@wo.cz>
 *                 ZDENEK SEBEK  <sebek@fel.cvut.cz>
 *
 * Czech Technical University in Prague
 *  Faculty of Electrical Engineering <www.fel.cvut.cz>
 *  Department of Control Engineering <dce.felk.cvut.cz>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 *                  -------------------------------------
 *
 * The following file is part of the RTPS packet dissector for Wireshark.
 *
 * RTPS protocol was developed by Real-Time Innovations, Inc. as wire
 * protocol for Data Distribution System.
 * Additional information at:
 *
 *   OMG DDS standards: http://portals.omg.org/dds/omg-dds-standard/
 *
 *   Older OMG DDS specification:
 *                             http://www.omg.org/cgi-bin/doc?ptc/2003-07-07
 *
 *   NDDS and RTPS information: http://www.rti.com/resources.html
 *
 * Vendor ID listing can be found at:
 *   https://www.dds-foundation.org/dds-rtps-vendor-and-product-ids/
 */

#include "config.h"

#include <epan/packet.h>
#include <epan/expert.h>
#include <epan/prefs.h>
#include "packet-rtps.h"
#include <epan/addr_resolv.h>
#include <epan/proto_data.h>
#include <epan/reassemble.h>
#include <epan/strutil.h>
#include "zlib.h"

void proto_register_rtps(void);
void proto_reg_handoff_rtps(void);

#define MAX_GUID_PREFIX_SIZE    (128)
#define MAX_GUID_SIZE           (160)
#define MAX_VENDOR_ID_SIZE      (128)
#define MAX_PARAM_SIZE          (256)
#define MAX_TIMESTAMP_SIZE      (128)

#define LONG_ALIGN(x)   (x = (x+3)&0xfffffffc)
#define SHORT_ALIGN(x)  (x = (x+1)&0xfffffffe)
#define MAX_ARRAY_DIMENSION 10
#define ALIGN_ME(offset, alignment)   \
        offset = (((offset) + ((alignment) - 1)) & ~((alignment) - 1))
#define ALIGN_ZERO(offset, alignment, zero) (offset -= zero, ALIGN_ME(offset, alignment), offset += zero)

#define KEY_COMMENT     ("  //@key")

#define LONG_ALIGN_ZERO(x,zero) (x -= zero, LONG_ALIGN(x), x += zero)
#define SHORT_ALIGN_ZERO(x,zero) (x -= zero, SHORT_ALIGN(x), x += zero)

#define DISSECTION_INFO_MAX_ELEMENTS_DEFAULT_VALUE          (100)
#define DISSECTION_INFO_ARRAY_MAX_ELEMENTS_DEFAULT_VALUE    (100)
#define DISSECTION_INFO_REMAINING_ELEMENTS_STR_d      "... %d items(s) remaining. The number of items shown is configurable through RTPS properties under Preferences/Protocols."
#define MAX_MEMBER_NAME                 (256)
#define HASHMAP_DISCRIMINATOR_CONSTANT  (-2)
#define UUID_SIZE                       (9)
#define LONG_ADDRESS_SIZE               (16)

typedef struct _union_member_mapping {
    guint64 union_type_id;
    guint64 member_type_id;
    gint32  discriminator;
    gchar member_name[MAX_MEMBER_NAME];
} union_member_mapping;

typedef struct _mutable_member_mapping {
    gint64 key;
    guint64 struct_type_id;
    guint64 member_type_id;
    guint32 member_id;
    gchar member_name[MAX_MEMBER_NAME];
} mutable_member_mapping;

typedef struct _dissection_element {
    guint64 type_id;
    guint16 flags;
    guint32 member_id;
    gchar member_name[MAX_MEMBER_NAME];
} dissection_element;

typedef enum {
    EXTENSIBILITY_INVALID = 1,
    EXTENSIBILITY_FINAL,
    EXTENSIBILITY_EXTENSIBLE,
    EXTENSIBILITY_MUTABLE
} RTICdrTypeObjectExtensibility;

typedef struct _dissection_info {
  guint64 type_id;
  gint member_kind;
  guint64 base_type_id;
  guint32 member_length;
  gchar member_name[MAX_MEMBER_NAME];

  RTICdrTypeObjectExtensibility extensibility;

  gint32 bound;
  guint32 num_elements;
  dissection_element* elements;

} dissection_info;

typedef enum {
    RTI_CDR_TK_NULL = 0,
    RTI_CDR_TK_SHORT,
    RTI_CDR_TK_LONG,
    RTI_CDR_TK_USHORT,
    RTI_CDR_TK_ULONG,
    RTI_CDR_TK_FLOAT,
    RTI_CDR_TK_DOUBLE,
    RTI_CDR_TK_BOOLEAN,
    RTI_CDR_TK_CHAR,
    RTI_CDR_TK_OCTET,
    RTI_CDR_TK_STRUCT,
    RTI_CDR_TK_UNION,
    RTI_CDR_TK_ENUM,
    RTI_CDR_TK_STRING,
    RTI_CDR_TK_SEQUENCE,
    RTI_CDR_TK_ARRAY,
    RTI_CDR_TK_ALIAS,
    RTI_CDR_TK_LONGLONG,
    RTI_CDR_TK_ULONGLONG,
    RTI_CDR_TK_LONGDOUBLE,
    RTI_CDR_TK_WCHAR,
    RTI_CDR_TK_WSTRING,
    RTI_CDR_TK_VALUE,
    RTI_CDR_TK_VALUE_PARAM
} RTICdrTCKind;

typedef enum {
    RTI_CDR_TYPE_OBJECT_TYPE_KIND_NO_TYPE=0,
    RTI_CDR_TYPE_OBJECT_TYPE_KIND_BOOLEAN_TYPE=1,
    RTI_CDR_TYPE_OBJECT_TYPE_KIND_BYTE_TYPE=2,
    RTI_CDR_TYPE_OBJECT_TYPE_KIND_INT_16_TYPE=3,
    RTI_CDR_TYPE_OBJECT_TYPE_KIND_UINT_16_TYPE=4,
    RTI_CDR_TYPE_OBJECT_TYPE_KIND_INT_32_TYPE=5,
    RTI_CDR_TYPE_OBJECT_TYPE_KIND_UINT_32_TYPE=6,
    RTI_CDR_TYPE_OBJECT_TYPE_KIND_INT_64_TYPE=7,
    RTI_CDR_TYPE_OBJECT_TYPE_KIND_UINT_64_TYPE=8,
    RTI_CDR_TYPE_OBJECT_TYPE_KIND_FLOAT_32_TYPE=9,
    RTI_CDR_TYPE_OBJECT_TYPE_KIND_FLOAT_64_TYPE=10,
    RTI_CDR_TYPE_OBJECT_TYPE_KIND_FLOAT_128_TYPE=11,
    RTI_CDR_TYPE_OBJECT_TYPE_KIND_CHAR_8_TYPE=12,
    RTI_CDR_TYPE_OBJECT_TYPE_KIND_CHAR_32_TYPE=13,
    RTI_CDR_TYPE_OBJECT_TYPE_KIND_ENUMERATION_TYPE=14,
    RTI_CDR_TYPE_OBJECT_TYPE_KIND_BITSET_TYPE=15,
    RTI_CDR_TYPE_OBJECT_TYPE_KIND_ALIAS_TYPE=16,
    RTI_CDR_TYPE_OBJECT_TYPE_KIND_ARRAY_TYPE=17,
    RTI_CDR_TYPE_OBJECT_TYPE_KIND_SEQUENCE_TYPE=18,
    RTI_CDR_TYPE_OBJECT_TYPE_KIND_STRING_TYPE=19,
    RTI_CDR_TYPE_OBJECT_TYPE_KIND_MAP_TYPE=20,
    RTI_CDR_TYPE_OBJECT_TYPE_KIND_UNION_TYPE=21,
    RTI_CDR_TYPE_OBJECT_TYPE_KIND_STRUCTURE_TYPE=22,
    RTI_CDR_TYPE_OBJECT_TYPE_KIND_ANNOTATION_TYPE=23,
    RTI_CDR_TYPE_OBJECT_TYPE_KIND_MODULE=24
} RTICdrTypeObjectTypeKind;

typedef struct _rtps_dissector_data {
  guint16 encapsulation_id;
  gboolean info_displayed;
  /* Represents the position of a sample within a batch. Since the
     position can be 0, we use -1 as not valid (not a batch) */
  gint position_in_batch;
} rtps_dissector_data;

static const value_string type_object_kind [] = {
  { RTI_CDR_TYPE_OBJECT_TYPE_KIND_NO_TYPE,          "NO_TYPE" },
  { RTI_CDR_TYPE_OBJECT_TYPE_KIND_BOOLEAN_TYPE,     "BOOLEAN_TYPE" },
  { RTI_CDR_TYPE_OBJECT_TYPE_KIND_BYTE_TYPE,        "BYTE_TYPE" },
  { RTI_CDR_TYPE_OBJECT_TYPE_KIND_INT_16_TYPE,      "INT_16_TYPE" },
  { RTI_CDR_TYPE_OBJECT_TYPE_KIND_UINT_16_TYPE,     "UINT_16_TYPE" },
  { RTI_CDR_TYPE_OBJECT_TYPE_KIND_INT_32_TYPE,      "INT_32_TYPE" },
  { RTI_CDR_TYPE_OBJECT_TYPE_KIND_UINT_32_TYPE,     "UINT_32_TYPE" },
  { RTI_CDR_TYPE_OBJECT_TYPE_KIND_INT_64_TYPE,      "INT_64_TYPE" },
  { RTI_CDR_TYPE_OBJECT_TYPE_KIND_UINT_64_TYPE,     "UINT_64_TYPE" },
  { RTI_CDR_TYPE_OBJECT_TYPE_KIND_FLOAT_32_TYPE,    "FLOAT_32_TYPE" },
  { RTI_CDR_TYPE_OBJECT_TYPE_KIND_FLOAT_64_TYPE,    "FLOAT_64_TYPE" },
  { RTI_CDR_TYPE_OBJECT_TYPE_KIND_FLOAT_128_TYPE,   "FLOAT_128_TYPE" },
  { RTI_CDR_TYPE_OBJECT_TYPE_KIND_CHAR_8_TYPE,      "CHAR_8_TYPE" },
  { RTI_CDR_TYPE_OBJECT_TYPE_KIND_CHAR_32_TYPE,     "CHAR_32_TYPE" },
  { RTI_CDR_TYPE_OBJECT_TYPE_KIND_ENUMERATION_TYPE, "ENUMERATION_TYPE" },
  { RTI_CDR_TYPE_OBJECT_TYPE_KIND_BITSET_TYPE,      "BITSET_TYPE" },
  { RTI_CDR_TYPE_OBJECT_TYPE_KIND_ALIAS_TYPE,       "ALIAS_TYPE" },
  { RTI_CDR_TYPE_OBJECT_TYPE_KIND_ARRAY_TYPE,       "ARRAY_TYPE" },
  { RTI_CDR_TYPE_OBJECT_TYPE_KIND_SEQUENCE_TYPE,    "SEQUENCE_TYPE" },
  { RTI_CDR_TYPE_OBJECT_TYPE_KIND_STRING_TYPE,      "STRING_TYPE" },
  { RTI_CDR_TYPE_OBJECT_TYPE_KIND_MAP_TYPE,         "MAP_TYPE" },
  { RTI_CDR_TYPE_OBJECT_TYPE_KIND_UNION_TYPE,       "UNION_TYPE" },
  { RTI_CDR_TYPE_OBJECT_TYPE_KIND_STRUCTURE_TYPE,   "STRUCTURE_TYPE" },
  { RTI_CDR_TYPE_OBJECT_TYPE_KIND_ANNOTATION_TYPE,  "ANNOTATION_TYPE" },
  { 0, NULL }
};

static wmem_map_t * dissection_infos = NULL;
static wmem_map_t * union_member_mappings = NULL;
static wmem_map_t * mutable_member_mappings = NULL;

/***************************************************************************/
/* Preferences                                                             */
/***************************************************************************/
static guint rtps_max_batch_samples_dissected = 16;
static guint rtps_max_data_type_elements = DISSECTION_INFO_MAX_ELEMENTS_DEFAULT_VALUE;
static guint rtps_max_array_data_type_elements = DISSECTION_INFO_ARRAY_MAX_ELEMENTS_DEFAULT_VALUE;
static gboolean enable_topic_info = TRUE;
static gboolean enable_rtps_reassembly = FALSE;
static gboolean enable_user_data_dissection = FALSE;
static gboolean enable_max_array_data_type_elements = TRUE;
static gboolean enable_max_data_type_elements = TRUE;
static dissector_table_t rtps_type_name_table;

/***************************************************************************/
/* Variable definitions                                                    */
/***************************************************************************/
#define RTPS_MAGIC_NUMBER   0x52545053 /* RTPS */
#define RTPX_MAGIC_NUMBER   0x52545058 /* RTPX */
#define RTPS_SEQUENCENUMBER_UNKNOWN     0xffffffff00000000 /* {-1,0} as uint64 */

/* Traffic type */
#define PORT_BASE                       (7400)
#define PORT_METATRAFFIC_UNICAST        (0)
#define PORT_USERTRAFFIC_MULTICAST      (1)
#define PORT_METATRAFFIC_MULTICAST      (2)
#define PORT_USERTRAFFIC_UNICAST        (3)

/* Flags defined in the 'flag' bitmask of a submessage */
#define FLAG_E                  (0x01)  /* Common to all the submessages */
#define FLAG_DATA_D             (0x02)
#define FLAG_DATA_D_v2          (0x04)
#define FLAG_DATA_A             (0x04)
#define FLAG_DATA_H             (0x08)
#define FLAG_DATA_Q             (0x10)
#define FLAG_DATA_Q_v2          (0x02)
#define FLAG_DATA_FRAG_Q        (0x02)
#define FLAG_DATA_FRAG_H        (0x04)
#define FLAG_DATA_I             (0x10)
#define FLAG_DATA_U             (0x20)
#define FLAG_NOKEY_DATA_Q       (0x02)
#define FLAG_NOKEY_DATA_D       (0x04)
#define FLAG_ACKNACK_F          (0x02)
#define FLAG_HEARTBEAT_F        (0x02)
#define FLAG_GAP_F              (0x02)
#define FLAG_INFO_TS_T          (0x02)
#define FLAG_INFO_REPLY_IP4_M   (0x02)
#define FLAG_INFO_REPLY_M       (0x02)
#define FLAG_RTPS_DATA_Q        (0x02)
#define FLAG_RTPS_DATA_D        (0x04)
#define FLAG_RTPS_DATA_K        (0x08)
#define FLAG_RTPS_DATA_FRAG_Q   (0x02)
#define FLAG_RTPS_DATA_FRAG_K   (0x04)
#define FLAG_RTPS_DATA_BATCH_Q  (0x02)
#define FLAG_SAMPLE_INFO_T      (0x01)
#define FLAG_SAMPLE_INFO_Q      (0x02)
#define FLAG_SAMPLE_INFO_O      (0x04)
#define FLAG_SAMPLE_INFO_D      (0x08)
#define FLAG_SAMPLE_INFO_I      (0x10)
#define FLAG_SAMPLE_INFO_K      (0x20)

#define FLAG_VIRTUAL_HEARTBEAT_V (0x02)
#define FLAG_VIRTUAL_HEARTBEAT_W (0x04)
#define FLAG_VIRTUAL_HEARTBEAT_N (0x08)

/* UDPv4 WAN Transport locator flags */
#define FLAG_UDPV4_WAN_LOCATOR_U (0x01)
#define FLAG_UDPV4_WAN_LOCATOR_P (0x02)
#define FLAG_UDPV4_WAN_LOCATOR_B (0x04)
#define FLAG_UDPV4_WAN_LOCATOR_R (0x08)

/* UDP WAN BINDING_PING submessage flags */
#define FLAG_UDPV4_WAN_BINDING_PING_FLAG_E (0x01)
#define FLAG_UDPV4_WAN_BINDING_PING_FLAG_L (0x02)
#define FLAG_UDPV4_WAN_BINDING_PING_FLAG_B (0x04)


/* The following PIDs are defined since RTPS 1.0 */
#define PID_PAD                                 (0x00)
#define PID_SENTINEL                            (0x01)
#define PID_PARTICIPANT_LEASE_DURATION          (0x02)
#define PID_TIME_BASED_FILTER                   (0x04)
#define PID_TOPIC_NAME                          (0x05)
#define PID_OWNERSHIP_STRENGTH                  (0x06)
#define PID_TYPE_NAME                           (0x07)
#define PID_METATRAFFIC_MULTICAST_IPADDRESS     (0x0b)
#define PID_DEFAULT_UNICAST_IPADDRESS           (0x0c)
#define PID_METATRAFFIC_UNICAST_PORT            (0x0d)
#define PID_DEFAULT_UNICAST_PORT                (0x0e)
#define PID_MULTICAST_IPADDRESS                 (0x11)
#define PID_PROTOCOL_VERSION                    (0x15)
#define PID_VENDOR_ID                           (0x16)
#define PID_RELIABILITY                         (0x1a)
#define PID_LIVELINESS                          (0x1b)
#define PID_DURABILITY                          (0x1d)
#define PID_DURABILITY_SERVICE                  (0x1e)
#define PID_OWNERSHIP                           (0x1f)
#define PID_PRESENTATION                        (0x21)
#define PID_DEADLINE                            (0x23)
#define PID_DESTINATION_ORDER                   (0x25)
#define PID_LATENCY_BUDGET                      (0x27)
#define PID_PARTITION                           (0x29)
#define PID_LIFESPAN                            (0x2b)
#define PID_USER_DATA                           (0x2c)
#define PID_GROUP_DATA                          (0x2d)
#define PID_TOPIC_DATA                          (0x2e)
#define PID_UNICAST_LOCATOR                     (0x2f)
#define PID_MULTICAST_LOCATOR                   (0x30)
#define PID_DEFAULT_UNICAST_LOCATOR             (0x31)
#define PID_METATRAFFIC_UNICAST_LOCATOR         (0x32)
#define PID_METATRAFFIC_MULTICAST_LOCATOR       (0x33)
#define PID_PARTICIPANT_MANUAL_LIVELINESS_COUNT (0x34)
#define PID_CONTENT_FILTER_PROPERTY             (0x35)
#define PID_PROPERTY_LIST_OLD                   (0x36) /* For compatibility between 4.2d and 4.2e */
#define PID_HISTORY                             (0x40)
#define PID_RESOURCE_LIMIT                      (0x41)
#define PID_EXPECTS_INLINE_QOS                  (0x43)
#define PID_PARTICIPANT_BUILTIN_ENDPOINTS       (0x44)
#define PID_METATRAFFIC_UNICAST_IPADDRESS       (0x45)
#define PID_METATRAFFIC_MULTICAST_PORT          (0x46)
#define PID_TYPECODE                            (0x47)
#define PID_PARTICIPANT_GUID                    (0x50)
#define PID_PARTICIPANT_ENTITY_ID               (0x51)
#define PID_GROUP_GUID                          (0x52)
#define PID_GROUP_ENTITY_ID                     (0x53)
#define PID_FILTER_SIGNATURE                    (0x55)
#define PID_COHERENT_SET                        (0x56)
#define PID_GROUP_COHERENT_SET                  (0x0063)
#define PID_END_COHERENT_SET                    (0x8022)
#define PID_END_GROUP_COHERENT_SET              (0x8023)
#define MIG_RTPS_PID_END_COHERENT_SET_SAMPLE_COUNT  (0x8024)

/* The following QoS are deprecated */
#define PID_PERSISTENCE                         (0x03)
#define PID_TYPE_CHECKSUM                       (0x08)
#define PID_TYPE2_NAME                          (0x09)
#define PID_TYPE2_CHECKSUM                      (0x0a)
#define PID_EXPECTS_ACK                         (0x10)
#define PID_MANAGER_KEY                         (0x12)
#define PID_SEND_QUEUE_SIZE                     (0x13)
#define PID_RELIABILITY_ENABLED                 (0x14)
#define PID_RECV_QUEUE_SIZE                     (0x18)
#define PID_VARGAPPS_SEQUENCE_NUMBER_LAST       (0x17)
#define PID_RELIABILITY_OFFERED                 (0x19)
#define PID_LIVELINESS_OFFERED                  (0x1c)
#define PID_OWNERSHIP_OFFERED                   (0x20)
#define PID_PRESENTATION_OFFERED                (0x22)
#define PID_DEADLINE_OFFERED                    (0x24)
#define PID_DESTINATION_ORDER_OFFERED           (0x26)
#define PID_LATENCY_BUDGET_OFFERED              (0x28)
#define PID_PARTITION_OFFERED                   (0x2a)

/* The following PIDs are defined since RTPS 2.0 */
#define PID_DEFAULT_MULTICAST_LOCATOR           (0x0048)
#define PID_TRANSPORT_PRIORITY                  (0x0049)
#define PID_CONTENT_FILTER_INFO                 (0x0055)
#define PID_DIRECTED_WRITE                      (0x0057)
#define PID_BUILTIN_ENDPOINT_SET                (0x0058)
#define PID_PROPERTY_LIST                       (0x0059)        /* RTI DDS 4.2e and newer */
#define PID_ENDPOINT_GUID                       (0x005a)
#define PID_TYPE_MAX_SIZE_SERIALIZED            (0x0060)
#define PID_ORIGINAL_WRITER_INFO                (0x0061)
#define PID_ENTITY_NAME                         (0x0062)
#define PID_KEY_HASH                            (0x0070)
#define PID_STATUS_INFO                         (0x0071)
#define PID_TYPE_OBJECT                         (0x0072)
#define PID_DATA_REPRESENTATION                 (0x0073)
#define PID_TYPE_CONSISTENCY                    (0x0074)
#define PID_EQUIVALENT_TYPE_NAME                (0x0075)
#define PID_BASE_TYPE_NAME                      (0x0076)
#define PID_BUILTIN_ENDPOINT_QOS                (0x0077)
#define PID_ENABLE_AUTHENTICATION               (0x0078)
#define PID_DOMAIN_ID                           (0x000f)
#define PID_DOMAIN_TAG                          (0x4014)

/* Vendor-specific: RTI */
#define PID_PRODUCT_VERSION                     (0x8000)
#define PID_PLUGIN_PROMISCUITY_KIND             (0x8001)
#define PID_ENTITY_VIRTUAL_GUID                 (0x8002)
#define PID_SERVICE_KIND                        (0x8003)
#define PID_TYPECODE_RTPS2                      (0x8004)        /* Was: 0x47 in RTPS 1.2 */
#define PID_DISABLE_POSITIVE_ACKS               (0x8005)
#define PID_LOCATOR_FILTER_LIST                 (0x8006)
#define PID_EXPECTS_VIRTUAL_HB                  (0x8009)
#define PID_ROLE_NAME                           (0x800a)
#define PID_ACK_KIND                            (0x800b)
#define PID_PEER_HOST_EPOCH                     (0x800e)
#define PID_RELATED_ORIGINAL_WRITER_INFO        (0x800f)/* inline QoS */
#define PID_RTI_DOMAIN_ID                       (0x800f)
#define PID_RELATED_READER_GUID                 (0x8010)/* inline QoS */
#define PID_TRANSPORT_INFO_LIST                 (0x8010)
#define PID_SOURCE_GUID                         (0x8011)/* inline QoS */
#define PID_DIRECT_COMMUNICATION                (0x8011)
#define PID_RELATED_SOURCE_GUID                 (0x8012)/* inline QoS */
#define PID_TOPIC_QUERY_GUID                    (0x8013)/* inline QoS */
#define PID_TOPIC_QUERY_PUBLICATION             (0x8014)
#define PID_ENDPOINT_PROPERTY_CHANGE_EPOCH      (0x8015)
#define PID_REACHABILITY_LEASE_DURATION         (0x8016)
#define PID_VENDOR_BUILTIN_ENDPOINT_SET         (0x8017)
#define PID_ENDPOINT_SECURITY_ATTRIBUTES        (0x8018)
#define PID_SAMPLE_SIGNATURE                    (0x8019)/* inline QoS */
#define PID_EXTENDED                            (0x3f01)
#define PID_LIST_END                            (0x3f02)
#define PID_UNICAST_LOCATOR_EX                  (0x8007)

#define PID_IDENTITY_TOKEN                      (0x1001)
#define PID_PERMISSIONS_TOKEN                   (0x1002)
#define PID_DATA_TAGS                           (0x1003)
#define PID_ENDPOINT_SECURITY_INFO              (0x1004)
#define PID_PARTICIPANT_SECURITY_INFO           (0x1005)
#define PID_PARTICIPANT_SECURITY_DIGITAL_SIGNATURE_ALGO     (0x1006)
#define PID_PARTICIPANT_SECURITY_KEY_ESTABLISHMENT_ALGO     (0x1007)
#define PID_PARTICIPANT_SECURITY_SYMMETRIC_CIPHER_ALGO      (0x1008)
#define PID_ENDPOINT_SECURITY_SYMMETRIC_CIPHER_ALGO         (0x1009)

#define PID_TYPE_OBJECT_LB                      (0x8021)

/* Vendor-specific: ADLink */
#define PID_ADLINK_WRITER_INFO                  (0x8001)
#define PID_ADLINK_READER_DATA_LIFECYCLE        (0x8002)
#define PID_ADLINK_WRITER_DATA_LIFECYCLE        (0x8003)
#define PID_ADLINK_ENDPOINT_GUID                (0x8004)
#define PID_ADLINK_SYNCHRONOUS_ENDPOINT         (0x8005)
#define PID_ADLINK_RELAXED_QOS_MATCHING         (0x8006)
#define PID_ADLINK_PARTICIPANT_VERSION_INFO     (0x8007)
#define PID_ADLINK_NODE_NAME                    (0x8008)
#define PID_ADLINK_EXEC_NAME                    (0x8009)
#define PID_ADLINK_PROCESS_ID                   (0x800a)
#define PID_ADLINK_SERVICE_TYPE                 (0x800b)
#define PID_ADLINK_ENTITY_FACTORY               (0x800c)
#define PID_ADLINK_WATCHDOG_SCHEDULING          (0x800d)
#define PID_ADLINK_LISTENER_SCHEDULING          (0x800e)
#define PID_ADLINK_SUBSCRIPTION_KEYS            (0x800f)
#define PID_ADLINK_READER_LIFESPAN              (0x8010)
#define PID_ADLINK_SHARE                        (0x8011)
#define PID_ADLINK_TYPE_DESCRIPTION             (0x8012)
#define PID_ADLINK_LAN_ID                       (0x8013)
#define PID_ADLINK_ENDPOINT_GID                 (0x8014)
#define PID_ADLINK_GROUP_GID                    (0x8015)
#define PID_ADLINK_EOTINFO                      (0x8016)
#define PID_ADLINK_PART_CERT_NAME               (0x8017)
#define PID_ADLINK_LAN_CERT_NAME                (0x8018)

/* appId.appKind possible values */
#define APPKIND_UNKNOWN                         (0x00)
#define APPKIND_MANAGED_APPLICATION             (0x01)
#define APPKIND_MANAGER                         (0x02)

#define RTI_SERVICE_REQUEST_ID_UNKNOWN                          0
#define RTI_SERVICE_REQUEST_ID_TOPIC_QUERY                      1
#define RTI_SERVICE_REQUEST_ID_LOCATOR_REACHABILITY             2

/* Predefined EntityId */
#define ENTITYID_UNKNOWN                        (0x00000000)
#define ENTITYID_PARTICIPANT                    (0x000001c1)
#define ENTITYID_BUILTIN_TOPIC_WRITER           (0x000002c2)
#define ENTITYID_BUILTIN_TOPIC_READER           (0x000002c7)
#define ENTITYID_BUILTIN_PUBLICATIONS_WRITER    (0x000003c2)
#define ENTITYID_BUILTIN_PUBLICATIONS_READER    (0x000003c7)
#define ENTITYID_BUILTIN_SUBSCRIPTIONS_WRITER   (0x000004c2)
#define ENTITYID_BUILTIN_SUBSCRIPTIONS_READER   (0x000004c7)
#define ENTITYID_BUILTIN_PARTICIPANT_WRITER     (0x000100c2)
#define ENTITYID_BUILTIN_PARTICIPANT_READER     (0x000100c7)
#define ENTITYID_P2P_BUILTIN_PARTICIPANT_MESSAGE_WRITER (0x000200c2)
#define ENTITYID_P2P_BUILTIN_PARTICIPANT_MESSAGE_READER (0x000200c7)

/* Secure DDS */
#define ENTITYID_P2P_BUILTIN_PARTICIPANT_STATELESS_WRITER          (0x000201c3)
#define ENTITYID_P2P_BUILTIN_PARTICIPANT_STATELESS_READER          (0x000201c4)
#define ENTITYID_SEDP_BUILTIN_PUBLICATIONS_SECURE_WRITER           (0xff0003c2)
#define ENTITYID_SEDP_BUILTIN_PUBLICATIONS_SECURE_READER           (0xff0003c7)
#define ENTITYID_SEDP_BUILTIN_SUBSCRIPTIONS_SECURE_WRITER          (0xff0004c2)
#define ENTITYID_SEDP_BUILTIN_SUBSCRIPTIONS_SECURE_READER          (0xff0004c7)
#define ENTITYID_P2P_BUILTIN_PARTICIPANT_MESSAGE_SECURE_WRITER     (0xff0200c2)
#define ENTITYID_P2P_BUILTIN_PARTICIPANT_MESSAGE_SECURE_READER     (0xff0200c7)
#define ENTITYID_P2P_BUILTIN_PARTICIPANT_VOLATILE_SECURE_WRITER    (0xff0202c3)
#define ENTITYID_P2P_BUILTIN_PARTICIPANT_VOLATILE_SECURE_READER    (0xff0202c4)
#define ENTITYID_SPDP_RELIABLE_BUILTIN_PARTICIPANT_SECURE_WRITER   (0xff0101c2)
#define ENTITYID_SPDP_RELIABLE_BUILTIN_PARTICIPANT_SECURE_READER   (0xff0101c7)

/* Vendor-specific: RTI */
#define ENTITYID_RTI_BUILTIN_SERVICE_REQUEST_WRITER             (0x00020082)
#define ENTITYID_RTI_BUILTIN_SERVICE_REQUEST_READER             (0x00020087)
#define ENTITYID_RTI_BUILTIN_LOCATOR_PING_WRITER                (0x00020182)
#define ENTITYID_RTI_BUILTIN_LOCATOR_PING_READER                (0x00020187)

/* Deprecated EntityId */
#define ENTITYID_APPLICATIONS_WRITER            (0x000001c2)
#define ENTITYID_APPLICATIONS_READER            (0x000001c7)
#define ENTITYID_CLIENTS_WRITER                 (0x000005c2)
#define ENTITYID_CLIENTS_READER                 (0x000005c7)
#define ENTITYID_SERVICES_WRITER                (0x000006c2)
#define ENTITYID_SERVICES_READER                (0x000006c7)
#define ENTITYID_MANAGERS_WRITER                (0x000007c2)
#define ENTITYID_MANAGERS_READER                (0x000007c7)
#define ENTITYID_APPLICATION_SELF               (0x000008c1)
#define ENTITYID_APPLICATION_SELF_WRITER        (0x000008c2)
#define ENTITYID_APPLICATION_SELF_READER        (0x000008c7)

/* Predefined Entity Kind */
#define ENTITYKIND_APPDEF_UNKNOWN               (0x00)
#define ENTITYKIND_APPDEF_PARTICIPANT           (0x01)
#define ENTITYKIND_APPDEF_WRITER_WITH_KEY       (0x02)
#define ENTITYKIND_APPDEF_WRITER_NO_KEY         (0x03)
#define ENTITYKIND_APPDEF_READER_NO_KEY         (0x04)
#define ENTITYKIND_APPDEF_READER_WITH_KEY       (0x07)
#define ENTITYKIND_BUILTIN_PARTICIPANT          (0xc1)
#define ENTITYKIND_BUILTIN_WRITER_WITH_KEY      (0xc2)
#define ENTITYKIND_BUILTIN_WRITER_NO_KEY        (0xc3)
#define ENTITYKIND_BUILTIN_READER_NO_KEY        (0xc4)
#define ENTITYKIND_BUILTIN_READER_WITH_KEY      (0xc7)

/* vendor specific RTI */
#define ENTITYKIND_RTI_BUILTIN_WRITER_WITH_KEY      (0x82)
#define ENTITYKIND_RTI_BUILTIN_WRITER_NO_KEY        (0x83)
#define ENTITYKIND_RTI_BUILTIN_READER_NO_KEY        (0x84)
#define ENTITYKIND_RTI_BUILTIN_READER_WITH_KEY      (0x87)

/* Submessage Type */
#define SUBMESSAGE_PAD                                  (0x01)
#define SUBMESSAGE_DATA                                 (0x02)
#define SUBMESSAGE_NOKEY_DATA                           (0x03)
#define SUBMESSAGE_ACKNACK                              (0x06)
#define SUBMESSAGE_HEARTBEAT                            (0x07)
#define SUBMESSAGE_GAP                                  (0x08)
#define SUBMESSAGE_INFO_TS                              (0x09)
#define SUBMESSAGE_INFO_SRC                             (0x0c)
#define SUBMESSAGE_INFO_REPLY_IP4                       (0x0d)
#define SUBMESSAGE_INFO_DST                             (0x0e)
#define SUBMESSAGE_INFO_REPLY                           (0x0f)

#define SUBMESSAGE_DATA_FRAG                            (0x10)  /* RTPS 2.0 Only */
#define SUBMESSAGE_NOKEY_DATA_FRAG                      (0x11)  /* RTPS 2.0 Only */
#define SUBMESSAGE_NACK_FRAG                            (0x12)  /* RTPS 2.0 Only */
#define SUBMESSAGE_HEARTBEAT_FRAG                       (0x13)  /* RTPS 2.0 Only */

#define SUBMESSAGE_RTPS_DATA_SESSION                    (0x14)  /* RTPS 2.1 only */
#define SUBMESSAGE_RTPS_DATA                            (0x15)  /* RTPS 2.1 only */
#define SUBMESSAGE_RTPS_DATA_FRAG                       (0x16)  /* RTPS 2.1 only */
#define SUBMESSAGE_ACKNACK_BATCH                        (0x17)  /* RTPS 2.1 only */
#define SUBMESSAGE_RTPS_DATA_BATCH                      (0x18)  /* RTPS 2.1 Only */
#define SUBMESSAGE_HEARTBEAT_BATCH                      (0x19)  /* RTPS 2.1 only */
#define SUBMESSAGE_ACKNACK_SESSION                      (0x1a)  /* RTPS 2.1 only */
#define SUBMESSAGE_HEARTBEAT_SESSION                    (0x1b)  /* RTPS 2.1 only */
#define SUBMESSAGE_APP_ACK                              (0x1c)
#define SUBMESSAGE_APP_ACK_CONF                         (0x1d)
#define SUBMESSAGE_HEARTBEAT_VIRTUAL                    (0x1e)
#define SUBMESSAGE_SEC_BODY                             (0x30)
#define SUBMESSAGE_SEC_PREFIX                           (0x31)
#define SUBMESSAGE_SEC_POSTFIX                          (0x32)
#define SUBMESSAGE_SRTPS_PREFIX                         (0x33)
#define SUBMESSAGE_SRTPS_POSTFIX                        (0x34)
#define SUBMESSAGE_RTI_CRC                              (0x80)
#define SUBMESSAGE_RTI_DATA_FRAG_SESSION                (0x81)  /* Vendor Specific */
#define SUBMESSAGE_RTI_UDP_WAN_BINDING_PING             (0x82)


/* An invalid IP Address:
 * Make sure the _STRING macro is bigger than a normal IP
 */
#define IPADDRESS_INVALID               (0)
#define IPADDRESS_INVALID_STRING        "ADDRESS_INVALID"

/* Identifies the value of an invalid port number:
 * Make sure the _STRING macro is bigger than a normal port
 */
#define PORT_INVALID                    (0)
#define PORT_INVALID_STRING             "PORT_INVALID"

/* Protocol Vendor Information (guint16) as per July 2020 */
#define RTPS_VENDOR_UNKNOWN              (0x0000)
#define RTPS_VENDOR_UNKNOWN_STRING       "VENDOR_ID_UNKNOWN (0x0000)"
#define RTPS_VENDOR_RTI_DDS              (0x0101)
#define RTPS_VENDOR_RTI_DDS_STRING       "Real-Time Innovations, Inc. - Connext DDS"
#define RTPS_VENDOR_ADL_DDS              (0x0102)
#define RTPS_VENDOR_ADL_DDS_STRING       "ADLink Ltd. - OpenSplice DDS"
#define RTPS_VENDOR_OCI                  (0x0103)
#define RTPS_VENDOR_OCI_STRING           "Object Computing, Inc. (OCI) - OpenDDS"
#define RTPS_VENDOR_MILSOFT              (0x0104)
#define RTPS_VENDOR_MILSOFT_STRING       "MilSoft"
#define RTPS_VENDOR_KONGSBERG            (0x0105)
#define RTPS_VENDOR_KONGSBERG_STRING     "Kongsberg - InterCOM DDS"
#define RTPS_VENDOR_TOC                  (0x0106)
#define RTPS_VENDOR_TOC_STRING           "TwinOaks Computing, Inc. - CoreDX DDS"
#define RTPS_VENDOR_LAKOTA_TSI           (0x0107)
#define RTPS_VENDOR_LAKOTA_TSI_STRING    "Lakota Technical Solutions, Inc."
#define RTPS_VENDOR_ICOUP                (0x0108)
#define RTPS_VENDOR_ICOUP_STRING         "ICOUP Consulting"
#define RTPS_VENDOR_ETRI                 (0x0109)
#define RTPS_VENDOR_ETRI_STRING          "Electronics and Telecommunication Research Institute (ETRI) - Diamond DDS"
#define RTPS_VENDOR_RTI_DDS_MICRO        (0x010A)
#define RTPS_VENDOR_RTI_DDS_MICRO_STRING "Real-Time Innovations, Inc. (RTI) - Connext DDS Micro"
#define RTPS_VENDOR_ADL_CAFE             (0x010B)
#define RTPS_VENDOR_ADL_CAFE_STRING      "ADLink Ltd. - Vortex Cafe"
#define RTPS_VENDOR_PT                   (0x010C)
#define RTPS_VENDOR_PT_STRING            "PrismTech"
#define RTPS_VENDOR_ADL_LITE             (0x010D)
#define RTPS_VENDOR_ADL_LITE_STRING      "ADLink Ltd. - Vortex Lite"
#define RTPS_VENDOR_TECHNICOLOR          (0x010E)
#define RTPS_VENDOR_TECHNICOLOR_STRING   "Technicolor Inc. - Qeo"
#define RTPS_VENDOR_EPROSIMA             (0x010F)
#define RTPS_VENDOR_EPROSIMA_STRING      "eProsima - Fast-RTPS"
#define RTPS_VENDOR_ECLIPSE              (0x0110)
#define RTPS_VENDOR_ECLIPSE_STRING       "Eclipse Foundation - Cyclone DDS"
#define RTPS_VENDOR_GURUM                (0x0111)
#define RTPS_VENDOR_GURUM_STRING         "GurumNetworks Ltd. - GurumDDS"

/* Data encapsulation */
#define ENCAPSULATION_CDR_BE            (0x0000)
#define ENCAPSULATION_CDR_LE            (0x0001)
#define ENCAPSULATION_PL_CDR_BE         (0x0002)
#define ENCAPSULATION_PL_CDR_LE         (0x0003)
#define ENCAPSULATION_CDR2_BE           (0x0006)
#define ENCAPSULATION_CDR2_LE           (0x0007)
#define ENCAPSULATION_D_CDR2_BE         (0x0008)
#define ENCAPSULATION_D_CDR2_LE         (0x0009)
#define ENCAPSULATION_PL_CDR2_BE        (0x000a)
#define ENCAPSULATION_PL_CDR2_LE        (0x000b)
#define ENCAPSULATION_SHMEM_REF_PLAIN        (0xC000)
#define ENCAPSULATION_SHMEM_REF_FLAT_DATA    (0xC001)

/* Data encapsulation options */
#define ENCAPSULATION_OPTIONS_COMPRESSION_BYTES_MASK            (0b11100)
#define GET_ENCAPSULATION_COMPRESSION_OPTIONS(encapsulation_options_in, compression_options_out) \
    (compression_options_out = (((encapsulation_options_in) & (ENCAPSULATION_OPTIONS_COMPRESSION_BYTES_MASK)) >> 2))
#define ENCAPSULATION_OPTIONS_COMPRESSION_EXTENDED_HEADER_VALUE ENCAPSULATION_OPTIONS_COMPRESSION_BYTES_MASK
#define ENCAPSULATION_OPTIONS_COMPRESSION_PADDING_BYTES_MASK    (0b11)


/* Parameter Liveliness */
#define LIVELINESS_AUTOMATIC            (0)
#define LIVELINESS_BY_PARTICIPANT       (1)
#define LIVELINESS_BY_TOPIC             (2)

/* Parameter Durability */
#define DURABILITY_VOLATILE             (0)
#define DURABILITY_TRANSIENT_LOCAL      (1)
#define DURABILITY_TRANSIENT            (2)
#define DURABILITY_PERSISTENT           (3)

/* Parameter Ownership */
#define OWNERSHIP_SHARED                (0)
#define OWNERSHIP_EXCLUSIVE             (1)

/* Parameter Presentation */
#define PRESENTATION_INSTANCE           (0)
#define PRESENTATION_TOPIC              (1)
#define PRESENTATION_GROUP              (2)

#define LOCATOR_KIND_INVALID            (-1)
#define LOCATOR_KIND_RESERVED           (0)
#define LOCATOR_KIND_UDPV4              (1)
#define LOCATOR_KIND_UDPV6              (2)
/* Vendor specific - rti */
#define LOCATOR_KIND_DTLS               (6)
#define LOCATOR_KIND_TCPV4_LAN          (8)
#define LOCATOR_KIND_TCPV4_WAN          (9)
#define LOCATOR_KIND_TLSV4_LAN          (10)
#define LOCATOR_KIND_TLSV4_WAN          (11)
#define LOCATOR_KIND_SHMEM              (0x01000000)
#define LOCATOR_KIND_TUDPV4             (0x01001001)
#define LOCATOR_KIND_UDPV4_WAN          (0x01000001)

/* History Kind */
#define HISTORY_KIND_KEEP_LAST          (0)
#define HISTORY_KIND_KEEP_ALL           (1)

/* Reliability Values */
#define RELIABILITY_BEST_EFFORT         (1)
#define RELIABILITY_RELIABLE            (2)

/* Destination Order */
#define BY_RECEPTION_TIMESTAMP          (0)
#define BY_SOURCE_TIMESTAMP             (1)

/* Member flags */
#define MEMBER_IS_KEY                   (1)
#define MEMBER_OPTIONAL                 (2)
#define MEMBER_SHAREABLE                (4)
#define MEMBER_UNION_DEFAULT            (8)
/* Participant message data kind */
#define PARTICIPANT_MESSAGE_DATA_KIND_UNKNOWN (0x00000000)
#define PARTICIPANT_MESSAGE_DATA_KIND_AUTOMATIC_LIVELINESS_UPDATE (0x00000001)
#define PARTICIPANT_MESSAGE_DATA_KIND_MANUAL_LIVELINESS_UPDATE (0x00000002)

/* Type Consistency Kinds */
#define DISALLOW_TYPE_COERCION  (0)
#define ALLOW_TYPE_COERCION     (1)

/* Ack kind */
#define PROTOCOL_ACKNOWLEDGMENT              (0)
#define APPLICATION_AUTO_ACKNOWLEDGMENT      (1)
#define APPLICATION_ORDERED_ACKNOWLEDGMENT   (2)
#define APPLICATION_EXPLICIT_ACKNOWLEDGMENT  (3)

#define CRYPTO_TRANSFORMATION_KIND_NONE          (0)
#define CRYPTO_TRANSFORMATION_KIND_AES128_GMAC   (1)
#define CRYPTO_TRANSFORMATION_KIND_AES128_GCM    (2)
#define CRYPTO_TRANSFORMATION_KIND_AES256_GMAC   (3)
#define CRYPTO_TRANSFORMATION_KIND_AES256_GCM    (4)

#define SECURITY_SYMMETRIC_CIPHER_BIT_AES128_GCM         0x00000001
#define SECURITY_SYMMETRIC_CIPHER_BIT_AES256_GCM         0x00000002
#define SECURITY_SYMMETRIC_CIPHER_BIT_CUSTOM_ALGORITHM   0x80000000

#define SECURITY_DIGITAL_SIGNATURE_BIT_RSASSAPSSMGF1SHA256_2048_SHA256  0x00000001
#define SECURITY_DIGITAL_SIGNATURE_BIT_RSASSAPKCS1V15_2048_SHA256       0x00000002
#define SECURITY_DIGITAL_SIGNATURE_BIT_ECDSA_P256_SHA256                0x00000004
#define SECURITY_DIGITAL_SIGNATURE_BIT_ECDSA_P384_SHA384                0x00000008
#define SECURITY_DIGITAL_SIGNATURE_BIT_CUSTOM_ALGORITHM                 0x80000000

#define SECURITY_KEY_ESTABLISHMENT_BIT_DHE_MODP2048256     0x00000001
#define SECURITY_KEY_ESTABLISHMENT_BIT_ECDHECEUM_P256      0x00000002
#define SECURITY_KEY_ESTABLISHMENT_BIT_ECDHECEUM_P384      0x00000004
#define SECURITY_KEY_ESTABLISHMENT_BIT_CUSTOM_ALGORITHM    0x80000000


#define TOPIC_INFO_ADD_GUID                      (0x01)
#define TOPIC_INFO_ADD_TYPE_NAME                 (0x02)
#define TOPIC_INFO_ADD_TOPIC_NAME                (0x04)
#define TOPIC_INFO_ALL_SET                       (0x07)

#define NOT_A_FRAGMENT                           (-1)

/*  */
#define RTI_OSAPI_COMPRESSION_CLASS_ID_NONE      (0)
#define RTI_OSAPI_COMPRESSION_CLASS_ID_ZLIB      (1)
#define RTI_OSAPI_COMPRESSION_CLASS_ID_BZIP2     (2)
#define RTI_OSAPI_COMPRESSION_CLASS_ID_AUTO      (G_MAXUINT32)

static int hf_rtps_dissection_boolean = -1;
static int hf_rtps_dissection_byte    = -1;
static int hf_rtps_dissection_int16   = -1;
static int hf_rtps_dissection_uint16  = -1;
static int hf_rtps_dissection_int32   = -1;
static int hf_rtps_dissection_uint32  = -1;
static int hf_rtps_dissection_int64   = -1;
static int hf_rtps_dissection_uint64  = -1;
static int hf_rtps_dissection_float   = -1;
static int hf_rtps_dissection_double  = -1;
static int hf_rtps_dissection_int128  = -1;
static int hf_rtps_dissection_string  = -1;

static const char *const SM_EXTRA_RPLUS  = "(r+)";
static const char *const SM_EXTRA_RMINUS = "(r-)";
static const char *const SM_EXTRA_WPLUS  = "(w+)";
static const char *const SM_EXTRA_WMINUS = "(w-)";
static const char *const SM_EXTRA_PPLUS  = "(p+)";
static const char *const SM_EXTRA_PMINUS = "(p-)";
static const char *const SM_EXTRA_TPLUS  = "(t+)";
static const char *const SM_EXTRA_TMINUS = "(t-)";

/***************************************************************************/
/* Protocol Fields Identifiers */
static int proto_rtps                           = -1;
static int hf_rtps_magic                        = -1;
static int hf_rtps_protocol_version             = -1;
static int hf_rtps_protocol_version_major       = -1;
static int hf_rtps_protocol_version_minor       = -1;
static int hf_rtps_vendor_id                    = -1;

static int hf_rtps_domain_id                    = -1;
static int hf_rtps_domain_tag                   = -1;
static int hf_rtps_participant_idx              = -1;
static int hf_rtps_nature_type                  = -1;

static int hf_rtps_guid_prefix_v1               = -1;
static int hf_rtps_guid_prefix               = -1;
static int hf_rtps_guid_prefix_src           = -1;
static int hf_rtps_guid_prefix_dst           = -1;
static int hf_rtps_host_id                      = -1;
static int hf_rtps_app_id                       = -1;
static int hf_rtps_app_id_instance_id           = -1;
static int hf_rtps_app_id_app_kind              = -1;

static int hf_rtps_sm_id                        = -1;
static int hf_rtps_sm_idv2                      = -1;
static int hf_rtps_sm_flags                     = -1;
static int hf_rtps_sm_flags2                    = -1;
static int hf_rtps_sm_octets_to_next_header     = -1;
static int hf_rtps_sm_guid_prefix_v1            = -1;
static int hf_rtps_sm_guid_prefix               = -1;
static int hf_rtps_sm_host_id                   = -1;
static int hf_rtps_sm_app_id                    = -1;
static int hf_rtps_sm_instance_id_v1            = -1;
static int hf_rtps_sm_app_kind                  = -1;
static int hf_rtps_sm_instance_id               = -1;
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
static int hf_rtps_parameter_id_inline_rti      = -1;
static int hf_rtps_parameter_id_toc             = -1;
static int hf_rtps_parameter_id_rti             = -1;
static int hf_rtps_parameter_id_adl             = -1;
static int hf_rtps_parameter_length             = -1;
static int hf_rtps_coherent_set_start           = -1;
static int hf_rtps_coherent_set_end             = -1;
static int hf_rtps_param_topic_name             = -1;
static int hf_rtps_param_strength               = -1;
static int hf_rtps_param_type_name              = -1;
static int hf_rtps_param_user_data              = -1;
static int hf_rtps_param_group_data             = -1;
static int hf_rtps_param_topic_data             = -1;
static int hf_rtps_param_content_filter_topic_name = -1;
static int hf_rtps_param_related_topic_name     = -1;
static int hf_rtps_param_filter_class_name      = -1;
static int hf_rtps_issue_data                   = -1;
static int hf_rtps_durability_service_cleanup_delay     = -1;
static int hf_rtps_liveliness_lease_duration            = -1;
static int hf_rtps_participant_lease_duration           = -1;
static int hf_rtps_time_based_filter_minimum_separation = -1;
static int hf_rtps_reliability_max_blocking_time        = -1;
static int hf_rtps_deadline_period                      = -1;
static int hf_rtps_latency_budget_duration              = -1;
static int hf_rtps_lifespan_duration                    = -1;
static int hf_rtps_persistence                          = -1;
static int hf_rtps_info_ts_timestamp                    = -1;
static int hf_rtps_locator_kind                         = -1;
static int hf_rtps_locator_port                         = -1;
/* static int hf_rtps_logical_port                         = -1; */
static int hf_rtps_locator_public_address_port          = -1;
static int hf_rtps_locator_ipv4                         = -1;
static int hf_rtps_locator_ipv6                         = -1;
static int hf_rtps_participant_builtin_endpoints        = -1;
static int hf_rtps_participant_manual_liveliness_count  = -1;
static int hf_rtps_history_depth                = -1;
static int hf_rtps_resource_limit_max_samples   = -1;
static int hf_rtps_resource_limit_max_instances = -1;
static int hf_rtps_resource_limit_max_samples_per_instances = -1;
static int hf_rtps_filter_bitmap                = -1;
static int hf_rtps_type_checksum                = -1;
static int hf_rtps_queue_size                   = -1;
static int hf_rtps_acknack_count              = -1;
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
static int hf_rtps_param_transport_priority     = -1;
static int hf_rtps_param_type_max_size_serialized = -1;
static int hf_rtps_param_entity_name            = -1;
static int hf_rtps_param_role_name              = -1;
static int hf_rtps_disable_positive_ack         = -1;
static int hf_rtps_participant_guid_v1          = -1;
static int hf_rtps_participant_guid             = -1;
static int hf_rtps_group_guid_v1                = -1;
static int hf_rtps_group_guid                   = -1;
static int hf_rtps_endpoint_guid                = -1;
static int hf_rtps_param_host_id                = -1;
static int hf_rtps_param_app_id                 = -1;
static int hf_rtps_param_instance_id            = -1;
static int hf_rtps_param_instance_id_v1         = -1;
static int hf_rtps_param_app_kind               = -1;
static int hf_rtps_param_entity                 = -1;
static int hf_rtps_param_entity_key             = -1;
static int hf_rtps_param_hf_entity_kind         = -1;
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
static int hf_rtps_param_expression_parameters_num  = -1;
static int hf_rtps_param_expression_parameters      = -1;
static int hf_rtps_locator_filter_list_num_channels = -1;
static int hf_rtps_locator_filter_list_filter_name  = -1;
static int hf_rtps_locator_filter_list_filter_exp   = -1;
static int hf_rtps_extra_flags                      = -1;
static int hf_rtps_param_builtin_endpoint_set_flags = -1;
static int hf_rtps_param_vendor_builtin_endpoint_set_flags = -1;
static int hf_rtps_param_endpoint_security_attributes      = -1;
static int hf_rtps_param_plugin_promiscuity_kind    = -1;
static int hf_rtps_param_service_kind               = -1;

static int hf_rtps_param_sample_signature_epoch             = -1;
static int hf_rtps_param_sample_signature_nonce             = -1;
static int hf_rtps_param_sample_signature_length            = -1;
static int hf_rtps_param_sample_signature_signature         = -1;
static int hf_rtps_secure_secure_data_length                = -1;
static int hf_rtps_secure_secure_data                       = -1;
static int hf_rtps_param_enable_authentication              = -1;
static int hf_rtps_param_builtin_endpoint_qos               = -1;
static int hf_rtps_secure_dataheader_transformation_kind    = -1;
static int hf_rtps_secure_dataheader_transformation_key_id  = -1;
static int hf_rtps_secure_dataheader_plugin_sec_header      = -1;
static int hf_rtps_secure_datatag_plugin_sec_tag            = -1;
static int hf_rtps_pgm                                      = -1;
static int hf_rtps_pgm_dst_participant_guid                 = -1;
static int hf_rtps_pgm_dst_endpoint_guid                    = -1;
static int hf_rtps_pgm_src_endpoint_guid                    = -1;
static int hf_rtps_source_participant_guid                  = -1;
static int hf_rtps_message_identity_source_guid             = -1;
static int hf_rtps_pgm_message_class_id                     = -1;
static int hf_rtps_pgm_data_holder_class_id                 = -1;
/* static int hf_rtps_pgm_data_holder_stringseq_size           = -1; */
/* static int hf_rtps_pgm_data_holder_stringseq_name           = -1; */
/* static int hf_rtps_pgm_data_holder_long_long                = -1; */

static int hf_rtps_param_timestamp_sec                          = -1;
static int hf_rtps_param_timestamp_fraction                     = -1;
static int hf_rtps_transportInfo_classId                        = -1;
static int hf_rtps_transportInfo_messageSizeMax                 = -1;
static int hf_rtps_param_app_ack_count                          = -1;
static int hf_rtps_param_app_ack_virtual_writer_count           = -1;
static int hf_rtps_param_app_ack_conf_virtual_writer_count      = -1;
static int hf_rtps_param_app_ack_conf_count                     = -1;
static int hf_rtps_param_app_ack_interval_payload_length        = -1;
static int hf_rtps_param_app_ack_interval_flags                 = -1;
static int hf_rtps_param_app_ack_interval_count                 = -1;
static int hf_rtps_param_app_ack_octets_to_next_virtual_writer  = -1;
static int hf_rtps_expects_virtual_heartbeat                    = -1;
static int hf_rtps_direct_communication                         = -1;
static int hf_rtps_param_peer_host_epoch                        = -1;
static int hf_rtps_param_endpoint_property_change_epoch         = -1;
static int hf_rtps_virtual_heartbeat_count                      = -1;
static int hf_rtps_virtual_heartbeat_num_virtual_guids          = -1;
static int hf_rtps_virtual_heartbeat_num_writers                = -1;
static int hf_rtps_param_extended_parameter                     = -1;
static int hf_rtps_param_extended_pid_length                    = -1;
static int hf_rtps_param_type_consistency_kind                  = -1;
static int hf_rtps_param_data_representation                    = -1;
static int hf_rtps_param_ignore_sequence_bounds                 = -1;
static int hf_rtps_param_ignore_string_bounds                   = -1;
static int hf_rtps_param_ignore_member_names                    = -1;
static int hf_rtps_param_prevent_type_widening                  = -1;
static int hf_rtps_param_force_type_validation                  = -1;
static int hf_rtps_param_ignore_enum_literal_names              = -1;
static int hf_rtps_parameter_data                               = -1;
static int hf_rtps_param_product_version_major                  = -1;
static int hf_rtps_param_product_version_minor                  = -1;
static int hf_rtps_param_product_version_release                = -1;
static int hf_rtps_param_product_version_release_as_char        = -1;
static int hf_rtps_param_product_version_revision               = -1;
static int hf_rtps_param_acknowledgment_kind                    = -1;
static int hf_rtps_param_topic_query_publication_enable         = -1;
static int hf_rtps_param_topic_query_publication_sessions       = -1;

static int hf_rtps_srm                                          = -1;
static int hf_rtps_srm_service_id                               = -1;
static int hf_rtps_srm_request_body                             = -1;
static int hf_rtps_srm_instance_id                              = -1;
static int hf_rtps_topic_query_selection_filter_class_name      = -1;
static int hf_rtps_topic_query_selection_filter_expression      = -1;
static int hf_rtps_topic_query_selection_num_parameters         = -1;
static int hf_rtps_topic_query_selection_filter_parameter       = -1;
static int hf_rtps_topic_query_topic_name                       = -1;
static int hf_rtps_topic_query_original_related_reader_guid     = -1;

static int hf_rtps_encapsulation_id                             = -1;
static int hf_rtps_encapsulation_kind                           = -1;
static int hf_rtps_octets_to_inline_qos                         = -1;
static int hf_rtps_filter_signature                             = -1;
static int hf_rtps_bitmap                                       = -1;
static int hf_rtps_acknack_analysis                             = -1;
static int hf_rtps_property_name                                = -1;
static int hf_rtps_property_value                               = -1;
static int hf_rtps_union                                        = -1;
static int hf_rtps_union_case                                   = -1;
static int hf_rtps_struct                                       = -1;
static int hf_rtps_member_name                                  = -1;
static int hf_rtps_sequence                                     = -1;
static int hf_rtps_array                                        = -1;
static int hf_rtps_bitfield                                     = -1;
static int hf_rtps_datatype                                     = -1;
static int hf_rtps_sequence_size                                = -1;
static int hf_rtps_guid                                         = -1;
static int hf_rtps_heartbeat_count                              = -1;
static int hf_rtps_encapsulation_options                        = -1;
static int hf_rtps_serialized_key                               = -1;
static int hf_rtps_serialized_data                              = -1;
static int hf_rtps_type_object_type_id_disc                     = -1;
static int hf_rtps_type_object_type_id                          = -1;
static int hf_rtps_type_object_primitive_type_id                = -1;
static int hf_rtps_type_object_base_type                        = -1;
static int hf_rtps_type_object_base_primitive_type_id           = -1;
static int hf_rtps_type_object_element_raw                      = -1;
static int hf_rtps_type_object_type_property_name               = -1;
static int hf_rtps_type_object_flags                            = -1;
static int hf_rtps_type_object_member_id                        = -1;
static int hf_rtps_type_object_annotation_value_d               = -1;
static int hf_rtps_type_object_annotation_value_16              = -1;
static int hf_rtps_type_object_union_label                      = -1;
static int hf_rtps_type_object_bound                            = -1;
static int hf_rtps_type_object_enum_constant_name               = -1;
static int hf_rtps_type_object_enum_constant_value              = -1;
static int hf_rtps_type_object_element_shared                   = -1;
static int hf_rtps_type_object_name                             = -1;
static int hf_rtps_type_object_element_module_name              = -1;
static int hf_rtps_uncompressed_serialized_length               = -1;
static int hf_rtps_compression_plugin_class_id                  = -1;
static int hf_rtps_compressed_serialized_type_object            = -1;
static int hf_rtps_pl_cdr_member                                = -1;
static int hf_rtps_pl_cdr_member_id                             = -1;
static int hf_rtps_pl_cdr_member_length                         = -1;
static int hf_rtps_pl_cdr_member_id_ext                         = -1;
static int hf_rtps_pl_cdr_member_length_ext                     = -1;
static int hf_rtps_dcps_publication_data_frame_number           = -1;
static int hf_rtps_udpv4_wan_locator_flags                      = -1;
static int hf_rtps_uuid                                         = -1;
static int hf_rtps_udpv4_wan_locator_public_ip                  = -1;
static int hf_rtps_udpv4_wan_locator_public_port                = -1;
static int hf_rtps_udpv4_wan_locator_local_ip                   = -1;
static int hf_rtps_udpv4_wan_locator_local_port                 = -1;
static int hf_rtps_udpv4_wan_binding_ping_port                  = -1;
static int hf_rtps_udpv4_wan_binding_ping_flags                 = -1;
static int hf_rtps_long_address                                 = -1;
static int hf_rtps_param_group_coherent_set                     = -1;
static int hf_rtps_param_end_group_coherent_set                 = -1;
static int hf_rtps_param_mig_end_coherent_set_sample_count      = -1;
static int hf_rtps_encapsulation_options_compression_plugin_class_id = -1;
static int hf_rtps_padding_bytes                                = -1;

/* Flag bits */
static int hf_rtps_flag_reserved80                              = -1;
static int hf_rtps_flag_reserved40                              = -1;
static int hf_rtps_flag_reserved20                              = -1;
static int hf_rtps_flag_reserved10                              = -1;
static int hf_rtps_flag_reserved08                              = -1;
static int hf_rtps_flag_reserved04                              = -1;
static int hf_rtps_flag_reserved02                              = -1;
static int hf_rtps_flag_reserved8000                            = -1;
static int hf_rtps_flag_reserved4000                            = -1;
static int hf_rtps_flag_reserved2000                            = -1;
static int hf_rtps_flag_reserved1000                            = -1;
static int hf_rtps_flag_reserved0800                            = -1;
static int hf_rtps_flag_reserved0400                            = -1;
static int hf_rtps_flag_reserved0200                            = -1;
static int hf_rtps_flag_reserved0100                            = -1;
static int hf_rtps_flag_reserved0080                            = -1;
static int hf_rtps_flag_reserved0040                            = -1;

static int hf_rtps_flag_builtin_endpoint_set_reserved           = -1;
static int hf_rtps_flag_unregister                              = -1;
static int hf_rtps_flag_inline_qos_v1                           = -1;
static int hf_rtps_flag_hash_key                                = -1;
static int hf_rtps_flag_alive                                   = -1;
static int hf_rtps_flag_data_present_v1                         = -1;
static int hf_rtps_flag_multisubmessage                         = -1;
static int hf_rtps_flag_endianness                              = -1;
static int hf_rtps_flag_status_info                             = -1;
static int hf_rtps_flag_data_present_v2                         = -1;
static int hf_rtps_flag_inline_qos_v2                           = -1;
static int hf_rtps_flag_final                                   = -1;
static int hf_rtps_flag_hash_key_rti                            = -1;
static int hf_rtps_flag_liveliness                              = -1;
static int hf_rtps_flag_multicast                               = -1;
static int hf_rtps_flag_data_serialized_key                     = -1;
static int hf_rtps_flag_data_frag_serialized_key                = -1;
static int hf_rtps_flag_timestamp                               = -1;
static int hf_rtps_flag_no_virtual_guids                        = -1;
static int hf_rtps_flag_multiple_writers                        = -1;
static int hf_rtps_flag_multiple_virtual_guids                  = -1;
static int hf_rtps_flag_serialize_key16                         = -1;
static int hf_rtps_flag_invalid_sample                          = -1;
static int hf_rtps_flag_data_present16                          = -1;
static int hf_rtps_flag_offsetsn_present                        = -1;
static int hf_rtps_flag_inline_qos16_v2                         = -1;
static int hf_rtps_flag_timestamp_present                       = -1;
static int hf_rtps_flag_unregistered                            = -1;
static int hf_rtps_flag_disposed                                = -1;
static int hf_rtps_param_status_info_flags                      = -1;

static int hf_rtps_flag_participant_announcer                   = -1;
static int hf_rtps_flag_participant_detector                    = -1;
static int hf_rtps_flag_publication_announcer                   = -1;
static int hf_rtps_flag_publication_detector                    = -1;
static int hf_rtps_flag_subscription_announcer                  = -1;
static int hf_rtps_flag_subscription_detector                   = -1;
static int hf_rtps_flag_participant_proxy_announcer             = -1;
static int hf_rtps_flag_participant_proxy_detector              = -1;
static int hf_rtps_flag_participant_state_announcer             = -1;
static int hf_rtps_flag_participant_state_detector              = -1;
static int hf_rtps_flag_participant_message_datawriter          = -1;
static int hf_rtps_flag_participant_message_datareader          = -1;
static int hf_rtps_flag_secure_publication_writer               = -1;
static int hf_rtps_flag_secure_publication_reader               = -1;
static int hf_rtps_flag_secure_subscription_writer              = -1;
static int hf_rtps_flag_secure_subscription_reader              = -1;
static int hf_rtps_flag_secure_participant_message_writer       = -1;
static int hf_rtps_flag_secure_participant_message_reader       = -1;
static int hf_rtps_flag_participant_stateless_message_writer    = -1;
static int hf_rtps_flag_participant_stateless_message_reader    = -1;
static int hf_rtps_flag_secure_participant_volatile_message_writer  = -1;
static int hf_rtps_flag_secure_participant_volatile_message_reader  = -1;
static int hf_rtps_flag_participant_secure_writer               = -1;
static int hf_rtps_flag_participant_secure_reader               = -1;
static int hf_rtps_flag_typeflag_final                          = -1;
static int hf_rtps_flag_typeflag_mutable                        = -1;
static int hf_rtps_flag_typeflag_nested                         = -1;
static int hf_rtps_flag_memberflag_key                          = -1;
static int hf_rtps_flag_memberflag_optional                     = -1;
static int hf_rtps_flag_memberflag_shareable                    = -1;
static int hf_rtps_flag_memberflag_union_default                = -1;
static int hf_rtps_flag_service_request_writer                  = -1;
static int hf_rtps_flag_service_request_reader                  = -1;
static int hf_rtps_flag_locator_ping_writer                     = -1;
static int hf_rtps_flag_locator_ping_reader                     = -1;
static int hf_rtps_flag_secure_service_request_writer           = -1;
static int hf_rtps_flag_cloud_discovery_service_announcer       = -1;
static int hf_rtps_flag_secure_service_request_reader           = -1;
static int hf_rtps_flag_security_access_protected               = -1;
static int hf_rtps_flag_security_discovery_protected            = -1;
static int hf_rtps_flag_security_submessage_protected           = -1;
static int hf_rtps_param_endpoint_security_symmetric_cipher_algorithms_used_bit                                       = -1;
static int hf_rtps_param_participant_security_symmetric_cipher_algorithms_builtin_endpoints_used_bit                  = -1;
static int hf_rtps_param_participant_security_symmetric_cipher_algorithms_builtin_endpoints_key_exchange_used_bit     = -1;
static int hf_rtps_param_participant_security_symmetric_cipher_algorithms_supported_mask    = -1;
static int hf_rtps_flag_security_symmetric_cipher_mask_aes128_gcm                           = -1;
static int hf_rtps_flag_security_symmetric_cipher_mask_aes256_gcm                           = -1;
static int hf_rtps_flag_security_symmetric_cipher_mask_custom_algorithm                     = -1;
static int hf_rtps_param_participant_security_digital_signature_algorithms_trust_chain_supported_mask                   = -1;
static int hf_rtps_param_participant_security_digital_signature_algorithms_trust_chain_used_mask                        = -1;
static int hf_rtps_param_participant_security_digital_signature_algorithms_auth_supported_mask                          = -1;
static int hf_rtps_flag_security_digital_signature_mask_rsassapssmgf1sha256_2048_sha256    = -1;
static int hf_rtps_flag_security_digital_signature_mask_rsassapkcs1v15_2048_sha256         = -1;
static int hf_rtps_flag_security_digital_signature_mask_ecdsa_p256_sha256                  = -1;
static int hf_rtps_flag_security_digital_signature_mask_ecdsa_p384_sha384                  = -1;
static int hf_rtps_flag_security_digital_signature_mask_custom_algorithm                   = -1;
static int hf_rtps_param_participant_security_key_establishment_algorithms_supported_mask  = -1;
static int hf_rtps_param_participant_security_key_establishment_algorithms_preferred_bit   = -1;
static int hf_rtps_param_participant_security_digital_signature_algorithms_auth_used_bit   = -1;
static int hf_rtps_flag_security_key_establishment_mask_dhe_modp2048256                    = -1;
static int hf_rtps_flag_security_key_establishment_mask_ecdheceum_p256                     = -1;
static int hf_rtps_flag_security_key_establishment_mask_ecdheceum_p384                     = -1;
static int hf_rtps_flag_security_key_establishment_mask_custom_algorithm                   = -1;
static int hf_rtps_flag_security_payload_protected                                        = -1;
static int hf_rtps_flag_endpoint_security_attribute_flag_is_read_protected                = -1;
static int hf_rtps_flag_endpoint_security_attribute_flag_is_write_protected               = -1;
static int hf_rtps_flag_endpoint_security_attribute_flag_is_discovery_protected           = -1;
static int hf_rtps_flag_endpoint_security_attribute_flag_is_submessage_protected          = -1;
static int hf_rtps_flag_endpoint_security_attribute_flag_is_payload_protected             = -1;
static int hf_rtps_flag_endpoint_security_attribute_flag_is_key_protected                 = -1;
static int hf_rtps_flag_endpoint_security_attribute_flag_is_liveliness_protected          = -1;
static int hf_rtps_flag_endpoint_security_attribute_flag_is_valid                         = -1;
static int hf_rtps_param_endpoint_security_attributes_mask                                = -1;
static int hf_rtps_flag_plugin_endpoint_security_attribute_flag_is_payload_encrypted      = -1;
static int hf_rtps_flag_plugin_endpoint_security_attribute_flag_is_key_encrypted          = -1;
static int hf_rtps_flag_plugin_endpoint_security_attribute_flag_is_liveliness_encrypted   = -1;
static int hf_rtps_flag_plugin_endpoint_security_attribute_flag_is_valid                  = -1;
static int hf_rtps_param_plugin_endpoint_security_attributes_mask                         = -1;
static int hf_rtps_flag_participant_security_attribute_flag_is_rtps_protected             = -1;
static int hf_rtps_flag_participant_security_attribute_flag_is_discovery_protected        = -1;
static int hf_rtps_flag_participant_security_attribute_flag_is_liveliness_protected       = -1;
static int hf_rtps_flag_participant_security_attribute_flag_is_valid                      = -1;
static int hf_rtps_param_participant_security_attributes_mask                             = -1;
static int hf_rtps_flag_plugin_participant_security_attribute_flag_is_rtps_encrypted              = -1;
static int hf_rtps_flag_plugin_participant_security_attribute_flag_is_discovery_encrypted         = -1;
static int hf_rtps_flag_plugin_participant_security_attribute_flag_is_liveliness_encrypted        = -1;
static int hf_rtps_flag_plugin_participant_security_attribute_flag_is_rtps_origin_encrypted       = -1;
static int hf_rtps_flag_plugin_participant_security_attribute_flag_is_discovery_origin_encrypted  = -1;
static int hf_rtps_flag_plugin_participant_security_attribute_flag_is_liveliness_origin_encrypted = -1;
static int hf_rtps_flag_plugin_participant_security_attribute_flag_is_valid                       = -1;
static int hf_rtps_param_plugin_participant_security_attributes_mask                              = -1;
static int hf_rtps_sm_rti_crc_number                            = -1;
static int hf_rtps_sm_rti_crc_result                            = -1;
static int hf_rtps_data_tag_name                                = -1;
static int hf_rtps_data_tag_value                               = -1;
static int hf_rtps_flag_udpv4_wan_locator_u                     = -1;
static int hf_rtps_flag_udpv4_wan_locator_p                     = -1;
static int hf_rtps_flag_udpv4_wan_locator_b                     = -1;
static int hf_rtps_flag_udpv4_wan_locator_r                     = -1;
static int hf_rtps_flag_udpv4_wan_binding_ping_e                = -1;
static int hf_rtps_flag_udpv4_wan_binding_ping_l                = -1;
static int hf_rtps_flag_udpv4_wan_binding_ping_b                = -1;

static int hf_rtps_fragments                                    = -1;
static int hf_rtps_fragment                                     = -1;
static int hf_rtps_fragment_overlap                             = -1;
static int hf_rtps_fragment_overlap_conflict                    = -1;
static int hf_rtps_fragment_multiple_tails                      = -1;
static int hf_rtps_fragment_too_long_fragment                   = -1;
static int hf_rtps_fragment_error                               = -1;
static int hf_rtps_fragment_count                               = -1;
static int hf_rtps_reassembled_in                               = -1;
static int hf_rtps_reassembled_length                           = -1;
static int hf_rtps_reassembled_data                             = -1;
static int hf_rtps_encapsulation_extended_compression_options   = -1;

/* Subtree identifiers */
static gint ett_rtps_dissection_tree = -1;
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
static gint ett_rtps_timestamp                  = -1;
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
static gint ett_rtps_locator_filter_locator                     = -1;
static gint ett_rtps_writer_heartbeat_virtual_list              = -1;
static gint ett_rtps_writer_heartbeat_virtual                   = -1;
static gint ett_rtps_virtual_guid_heartbeat_virtual_list        = -1;
static gint ett_rtps_virtual_guid_heartbeat_virtual             = -1;
static gint ett_rtps_app_ack_virtual_writer_interval_list       = -1;
static gint ett_rtps_app_ack_virtual_writer_interval            = -1;
static gint ett_rtps_transport_info                             = -1;
static gint ett_rtps_app_ack_virtual_writer_list                = -1;
static gint ett_rtps_app_ack_virtual_writer                     = -1;
static gint ett_rtps_product_version                            = -1;
static gint ett_rtps_property_list                              = -1;
static gint ett_rtps_property                                   = -1;
static gint ett_rtps_topic_info                                 = -1;
static gint ett_rtps_topic_info_dw_qos                          = -1;
static gint ett_rtps_type_object                                = -1;
static gint ett_rtps_type_library                               = -1;
static gint ett_rtps_type_element                               = -1;
static gint ett_rtps_type_annotation_usage_list                 = -1;
static gint ett_rtps_type_enum_constant                         = -1;
static gint ett_rtps_type_bound_list                            = -1;
static gint ett_rtps_secure_payload_tree                        = -1;
static gint ett_rtps_secure_dataheader_tree                     = -1;
static gint ett_rtps_pgm_data                                   = -1;
static gint ett_rtps_message_identity                           = -1;
static gint ett_rtps_related_message_identity                   = -1;
static gint ett_rtps_data_holder_seq                            = -1;
static gint ett_rtps_data_holder                                = -1;
static gint ett_rtps_data_holder_properties                     = -1;
static gint ett_rtps_property_tree                              = -1;
static gint ett_rtps_param_header_tree                          = -1;
static gint ett_rtps_service_request_tree                       = -1;
static gint ett_rtps_locator_ping_tree                          = -1;
static gint ett_rtps_locator_reachability_tree                  = -1;
static gint ett_rtps_custom_dissection_info                     = -1;
static gint ett_rtps_locator_list_tree                          = -1;
static gint ett_rtps_topic_query_tree                           = -1;
static gint ett_rtps_topic_query_selection_tree                 = -1;
static gint ett_rtps_topic_query_filter_params_tree             = -1;
static gint ett_rtps_data_member                                = -1;
static gint ett_rtps_data_tag_seq                               = -1;
static gint ett_rtps_data_tag_item                              = -1;
static gint ett_rtps_fragment                                   = -1;
static gint ett_rtps_fragments                                  = -1;
static gint ett_rtps_data_representation                        = -1;
static gint ett_rtps_decompressed_type_object                   = -1;
static gint ett_rtps_info_remaining_items                       = -1;
static gint ett_rtps_data_encapsulation_options                 = -1;
static gint ett_rtps_decompressed_serialized_data               = -1;

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
static expert_field pid_type_csonsistency_invalid_size = EI_INIT;
static expert_field ei_rtps_uncompression_error = EI_INIT;

/***************************************************************************/
/* Value-to-String Tables */
static const value_string vendor_vals[] = {
  { RTPS_VENDOR_UNKNOWN,       RTPS_VENDOR_UNKNOWN_STRING},
  { RTPS_VENDOR_RTI_DDS,       RTPS_VENDOR_RTI_DDS_STRING},
  { RTPS_VENDOR_ADL_DDS,       RTPS_VENDOR_ADL_DDS_STRING},
  { RTPS_VENDOR_OCI,           RTPS_VENDOR_OCI_STRING},
  { RTPS_VENDOR_MILSOFT,       RTPS_VENDOR_MILSOFT_STRING},
  { RTPS_VENDOR_KONGSBERG,     RTPS_VENDOR_KONGSBERG_STRING},
  { RTPS_VENDOR_TOC,           RTPS_VENDOR_TOC_STRING},
  { RTPS_VENDOR_LAKOTA_TSI,    RTPS_VENDOR_LAKOTA_TSI_STRING},
  { RTPS_VENDOR_ICOUP,         RTPS_VENDOR_ICOUP_STRING},
  { RTPS_VENDOR_ETRI,          RTPS_VENDOR_ETRI_STRING},
  { RTPS_VENDOR_RTI_DDS_MICRO, RTPS_VENDOR_RTI_DDS_MICRO_STRING},
  { RTPS_VENDOR_ADL_CAFE,      RTPS_VENDOR_ADL_CAFE_STRING},
  { RTPS_VENDOR_PT,            RTPS_VENDOR_PT_STRING},
  { RTPS_VENDOR_ADL_LITE,      RTPS_VENDOR_ADL_LITE_STRING},
  { RTPS_VENDOR_TECHNICOLOR,   RTPS_VENDOR_TECHNICOLOR_STRING},
  { RTPS_VENDOR_EPROSIMA,      RTPS_VENDOR_EPROSIMA_STRING},
  { RTPS_VENDOR_ECLIPSE,       RTPS_VENDOR_ECLIPSE_STRING},
  { RTPS_VENDOR_GURUM,         RTPS_VENDOR_GURUM_STRING},
  { 0, NULL }
};

static const value_string entity_id_vals[] = {
  { ENTITYID_UNKNOWN,                                           "ENTITYID_UNKNOWN" },
  { ENTITYID_PARTICIPANT,                                       "ENTITYID_PARTICIPANT" },
  { ENTITYID_BUILTIN_TOPIC_WRITER,                              "ENTITYID_BUILTIN_TOPIC_WRITER" },
  { ENTITYID_BUILTIN_TOPIC_READER,                              "ENTITYID_BUILTIN_TOPIC_READER" },
  { ENTITYID_BUILTIN_PUBLICATIONS_WRITER,                       "ENTITYID_BUILTIN_PUBLICATIONS_WRITER" },
  { ENTITYID_BUILTIN_PUBLICATIONS_READER,                       "ENTITYID_BUILTIN_PUBLICATIONS_READER" },
  { ENTITYID_BUILTIN_SUBSCRIPTIONS_WRITER,                      "ENTITYID_BUILTIN_SUBSCRIPTIONS_WRITER" },
  { ENTITYID_BUILTIN_SUBSCRIPTIONS_READER,                      "ENTITYID_BUILTIN_SUBSCRIPTIONS_READER" },
  { ENTITYID_BUILTIN_PARTICIPANT_WRITER,                        "ENTITYID_BUILTIN_PARTICIPANT_WRITER" },
  { ENTITYID_BUILTIN_PARTICIPANT_READER,                        "ENTITYID_BUILTIN_PARTICIPANT_READER" },
  { ENTITYID_P2P_BUILTIN_PARTICIPANT_MESSAGE_WRITER,            "ENTITYID_P2P_BUILTIN_PARTICIPANT_MESSAGE_WRITER" },
  { ENTITYID_P2P_BUILTIN_PARTICIPANT_MESSAGE_READER,            "ENTITYID_P2P_BUILTIN_PARTICIPANT_MESSAGE_READER" },
  { ENTITYID_SEDP_BUILTIN_PUBLICATIONS_SECURE_WRITER,           "ENTITYID_SEDP_BUILTIN_PUBLICATIONS_SECURE_WRITER" },
  { ENTITYID_SEDP_BUILTIN_PUBLICATIONS_SECURE_READER,           "ENTITYID_SEDP_BUILTIN_PUBLICATIONS_SECURE_READER" },
  { ENTITYID_SEDP_BUILTIN_SUBSCRIPTIONS_SECURE_WRITER,          "ENTITYID_SEDP_BUILTIN_SUBSCRIPTIONS_SECURE_WRITER" },
  { ENTITYID_SEDP_BUILTIN_SUBSCRIPTIONS_SECURE_READER,          "ENTITYID_SEDP_BUILTIN_SUBSCRIPTIONS_SECURE_READER" },
  { ENTITYID_P2P_BUILTIN_PARTICIPANT_MESSAGE_SECURE_WRITER,     "ENTITYID_P2P_BUILTIN_PARTICIPANT_MESSAGE_SECURE_WRITER" },
  { ENTITYID_P2P_BUILTIN_PARTICIPANT_MESSAGE_SECURE_READER,     "ENTITYID_P2P_BUILTIN_PARTICIPANT_MESSAGE_SECURE_READER" },
  { ENTITYID_P2P_BUILTIN_PARTICIPANT_STATELESS_WRITER,          "ENTITYID_P2P_BUILTIN_PARTICIPANT_STATELESS_WRITER" },
  { ENTITYID_P2P_BUILTIN_PARTICIPANT_STATELESS_READER,          "ENTITYID_P2P_BUILTIN_PARTICIPANT_STATELESS_READER" },
  { ENTITYID_P2P_BUILTIN_PARTICIPANT_VOLATILE_SECURE_WRITER,    "ENTITYID_P2P_BUILTIN_PARTICIPANT_VOLATILE_SECURE_WRITER" },
  { ENTITYID_P2P_BUILTIN_PARTICIPANT_VOLATILE_SECURE_READER,    "ENTITYID_P2P_BUILTIN_PARTICIPANT_VOLATILE_SECURE_READER" },
  { ENTITYID_SPDP_RELIABLE_BUILTIN_PARTICIPANT_SECURE_WRITER,   "ENTITYID_SPDP_RELIABLE_BUILTIN_PARTICIPANT_SECURE_WRITER"},
  { ENTITYID_SPDP_RELIABLE_BUILTIN_PARTICIPANT_SECURE_READER,   "ENTITYID_SPDP_RELIABLE_BUILTIN_PARTICIPANT_SECURE_READER"},

  /* vendor specific - RTI */
  { ENTITYID_RTI_BUILTIN_LOCATOR_PING_WRITER,       "ENTITYID_RTI_BUILTIN_LOCATOR_PING_WRITER" },
  { ENTITYID_RTI_BUILTIN_LOCATOR_PING_READER,       "ENTITYID_RTI_BUILTIN_LOCATOR_PING_READER" },
  { ENTITYID_RTI_BUILTIN_SERVICE_REQUEST_WRITER,    "ENTITYID_RTI_BUILTIN_SERVICE_REQUEST_WRITER" },
  { ENTITYID_RTI_BUILTIN_SERVICE_REQUEST_READER,    "ENTITYID_RTI_BUILTIN_SERVICE_REQUEST_READER" },

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
  { ENTITYKIND_RTI_BUILTIN_WRITER_WITH_KEY,     "RTI Built-in writer (with key)" },
  { ENTITYKIND_RTI_BUILTIN_WRITER_NO_KEY,       "RTI Built-in writer (no key)" },
  { ENTITYKIND_RTI_BUILTIN_READER_WITH_KEY,     "RTI Built-in reader (with key)" },
  { ENTITYKIND_RTI_BUILTIN_READER_NO_KEY,       "RTI Built-in reader (no key)" },
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
  { LOCATOR_KIND_DTLS,         "LOCATOR_KIND_DTLS" },
  { LOCATOR_KIND_TCPV4_LAN,    "LOCATOR_KIND_TCPV4_LAN" },
  { LOCATOR_KIND_TCPV4_WAN,    "LOCATOR_KIND_TCPV4_WAN" },
  { LOCATOR_KIND_TLSV4_LAN,    "LOCATOR_KIND_TLSV4_LAN" },
  { LOCATOR_KIND_TLSV4_WAN,    "LOCATOR_KIND_TLSV4_WAN" },
  { LOCATOR_KIND_SHMEM,        "LOCATOR_KIND_SHMEM" },
  { LOCATOR_KIND_TUDPV4,       "LOCATOR_KIND_TUDPV4" },
  { LOCATOR_KIND_RESERVED,     "LOCATOR_KIND_RESERVED" },
  { LOCATOR_KIND_UDPV4_WAN,    "LOCATOR_KIND_UDPV4_WAN" },
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
  { SUBMESSAGE_PAD,                     "PAD" },
  { SUBMESSAGE_RTPS_DATA,               "DATA" },
  { SUBMESSAGE_RTPS_DATA_FRAG,          "DATA_FRAG" },
  { SUBMESSAGE_RTI_DATA_FRAG_SESSION,   "DATA_FRAG_SESSION" },
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
  { SUBMESSAGE_APP_ACK,                 "APP_ACK" },
  { SUBMESSAGE_APP_ACK_CONF,            "APP_ACK_CONF" },
  { SUBMESSAGE_HEARTBEAT_VIRTUAL,       "HEARTBEAT_VIRTUAL" },
  { SUBMESSAGE_SEC_BODY,                "SEC_BODY" },
  { SUBMESSAGE_SEC_PREFIX,              "SEC_PREFIX" },
  { SUBMESSAGE_SEC_POSTFIX,             "SEC_POSTFIX" },
  { SUBMESSAGE_SRTPS_PREFIX,            "SRTPS_PREFIX" },
  { SUBMESSAGE_SRTPS_POSTFIX,           "SRTPS_POSTFIX" },
  /* Deprecated submessages */
  { SUBMESSAGE_DATA,              "DATA_deprecated" },
  { SUBMESSAGE_NOKEY_DATA,        "NOKEY_DATA_deprecated" },
  { SUBMESSAGE_DATA_FRAG,         "DATA_FRAG_deprecated" },
  { SUBMESSAGE_NOKEY_DATA_FRAG,   "NOKEY_DATA_FRAG_deprecated" },
  { 0, NULL }
};

static const value_string submessage_id_rti[] = {
  { SUBMESSAGE_RTI_CRC,                  "RTI_CRC" },
  { SUBMESSAGE_RTI_UDP_WAN_BINDING_PING, "RTI_BINDING_PING" },
  { SUBMESSAGE_RTI_DATA_FRAG_SESSION,    "DATA_FRAG_SESSION" },
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
  { PID_METATRAFFIC_UNICAST_LOCATOR,    "PID_METATRAFFIC_UNICAST_LOCATOR" },
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

static const value_string parameter_id_inline_qos_rti[] = {
  { PID_RELATED_ORIGINAL_WRITER_INFO,   "PID_RELATED_ORIGINAL_WRITER_INFO" },
  { PID_RELATED_SOURCE_GUID,            "PID_RELATED_SOURCE_GUID" },
  { PID_RELATED_READER_GUID,            "PID_RELATED_READER_GUID" },
  { PID_SOURCE_GUID,                    "PID_SOURCE_GUID" },
  { PID_TOPIC_QUERY_GUID,               "PID_TOPIC_QUERY_GUID" },
  { PID_SAMPLE_SIGNATURE,               "PID_SAMPLE_SIGNATURE" },
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
  { PID_METATRAFFIC_UNICAST_LOCATOR,    "PID_METATRAFFIC_UNICAST_LOCATOR" },
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
  { PID_DATA_REPRESENTATION,            "PID_DATA_REPRESENTATION" },
  { PID_TYPE_CONSISTENCY,               "PID_TYPE_CONSISTENCY" },
  { PID_BUILTIN_ENDPOINT_QOS,           "PID_BUILTIN_ENDPOINT_QOS" },
  { PID_ENABLE_AUTHENTICATION,          "PID_ENABLE_AUTHENTICATION" },
  { PID_IDENTITY_TOKEN,                 "PID_IDENTITY_TOKEN" },
  { PID_PERMISSIONS_TOKEN,              "PID_PERMISSIONS_TOKEN" },
  { PID_DATA_TAGS,                      "PID_DATA_TAGS" },
  { PID_ENDPOINT_SECURITY_INFO,         "PID_ENDPOINT_SECURITY_INFO" },
  { PID_PARTICIPANT_SECURITY_INFO,      "PID_PARTICIPANT_SECURITY_INFO" },
  { PID_PARTICIPANT_SECURITY_DIGITAL_SIGNATURE_ALGO,    "PID_PARTICIPANT_SECURITY_DIGITAL_SIGNATURE_ALGO" },
  { PID_PARTICIPANT_SECURITY_KEY_ESTABLISHMENT_ALGO,    "PID_PARTICIPANT_SECURITY_KEY_ESTABLISHMENT_ALGO" },
  { PID_PARTICIPANT_SECURITY_SYMMETRIC_CIPHER_ALGO,     "PID_PARTICIPANT_SECURITY_SYMMETRIC_CIPHER_ALGO" },
  { PID_ENDPOINT_SECURITY_SYMMETRIC_CIPHER_ALGO,        "PID_ENDPOINT_SECURITY_SYMMETRIC_CIPHER_ALGO" },
  { PID_DOMAIN_ID,                      "PID_DOMAIN_ID" },
  { PID_DOMAIN_TAG,                     "PID_DOMAIN_TAG" },
  { PID_GROUP_COHERENT_SET,             "PID_GROUP_COHERENT_SET" },
  { PID_END_COHERENT_SET,               "PID_END_COHERENT_SET" },
  { PID_END_GROUP_COHERENT_SET,         "PID_END_GROUP_COHERENT_SET" },
  { MIG_RTPS_PID_END_COHERENT_SET_SAMPLE_COUNT,  "MIG_RTPS_PID_END_COHERENT_SET_SAMPLE_COUNT" },

  /* The following PID are deprecated */
  { PID_DEADLINE_OFFERED,               "PID_DEADLINE_OFFERED [deprecated]" },
  { PID_PERSISTENCE,                    "PID_PERSISTENCE [deprecated]" },
  { PID_TYPE_CHECKSUM,                  "PID_TYPE_CHECKSUM [deprecated]" },
  { PID_TYPE2_NAME,                     "PID_TYPE2_NAME [deprecated]" },
  { PID_TYPE2_CHECKSUM,                 "PID_TYPE2_CHECKSUM [deprecated]" },
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
  { PID_EXTENDED,                       "PID_EXTENDED" },
  { 0, NULL }
};

static const value_string parameter_id_rti_vals[] = {
  /* Vendor specific: RTI */
  { PID_PRODUCT_VERSION,                "PID_PRODUCT_VERSION" },
  { PID_PLUGIN_PROMISCUITY_KIND,        "PID_PLUGIN_PROMISCUITY_KIND" },
  { PID_ENTITY_VIRTUAL_GUID,            "PID_ENTITY_VIRTUAL_GUID" },
  { PID_SERVICE_KIND,                   "PID_SERVICE_KIND" },
  { PID_TYPECODE_RTPS2,                 "PID_TYPECODE" },
  { PID_DISABLE_POSITIVE_ACKS,          "PID_DISABLE_POSITIVE_ACKS" },
  { PID_LOCATOR_FILTER_LIST,            "PID_LOCATOR_FILTER_LIST" },
  { PID_ROLE_NAME,                      "PID_ROLE_NAME"},
  { PID_ACK_KIND,                       "PID_ACK_KIND" },
  { PID_PEER_HOST_EPOCH,                "PID_PEER_HOST_EPOCH" },
  { PID_TRANSPORT_INFO_LIST,            "PID_TRANSPORT_INFO_LIST" },
  { PID_DIRECT_COMMUNICATION,           "PID_DIRECT_COMMUNICATION" },
  { PID_TYPE_OBJECT,                    "PID_TYPE_OBJECT" },
  { PID_EXPECTS_VIRTUAL_HB,             "PID_EXPECTS_VIRTUAL_HB" },
  { PID_RTI_DOMAIN_ID,                  "PID_RTI_DOMAIN_ID" },
  { PID_TOPIC_QUERY_PUBLICATION,        "PID_TOPIC_QUERY_PUBLICATION" },
  { PID_ENDPOINT_PROPERTY_CHANGE_EPOCH, "PID_ENDPOINT_PROPERTY_CHANGE_EPOCH" },
  { PID_REACHABILITY_LEASE_DURATION,    "PID_REACHABILITY_LEASE_DURATION" },
  { PID_VENDOR_BUILTIN_ENDPOINT_SET,    "PID_VENDOR_BUILTIN_ENDPOINT_SET" },
  { PID_ENDPOINT_SECURITY_ATTRIBUTES,   "PID_ENDPOINT_SECURITY_ATTRIBUTES" },
  { PID_TYPE_OBJECT_LB,                 "PID_TYPE_OBJECT_LB" },
  { PID_UNICAST_LOCATOR_EX,             "PID_UNICAST_LOCATOR_EX"},
  { 0, NULL }
};
static const value_string parameter_id_toc_vals[] = {
  /* Vendor specific: Twin Oaks Computing */
  { PID_TYPECODE_RTPS2,                 "PID_TYPECODE_RTPS2" },
  { 0, NULL }
};

static const value_string parameter_id_adl_vals[] = {
  /* Vendor specific: ADLink Ltd. */
  { PID_ADLINK_WRITER_INFO,                  "PID_ADLINK_WRITER_INFO" },
  { PID_ADLINK_READER_DATA_LIFECYCLE,        "PID_ADLINK_READER_DATA_LIFECYCLE" },
  { PID_ADLINK_WRITER_DATA_LIFECYCLE,        "PID_ADLINK_WRITER_DATA_LIFECYCLE" },
  { PID_ADLINK_ENDPOINT_GUID,                "PID_ADLINK_ENDPOINT_GUID" },
  { PID_ADLINK_SYNCHRONOUS_ENDPOINT,         "PID_ADLINK_SYNCHRONOUS_ENDPOINT" },
  { PID_ADLINK_RELAXED_QOS_MATCHING,         "PID_ADLINK_RELAXED_QOS_MATCHING" },
  { PID_ADLINK_PARTICIPANT_VERSION_INFO,     "PID_ADLINK_PARTICIPANT_VERSION_INFO" },
  { PID_ADLINK_NODE_NAME,                    "PID_ADLINK_NODE_NAME" },
  { PID_ADLINK_EXEC_NAME,                    "PID_ADLINK_EXEC_NAME" },
  { PID_ADLINK_PROCESS_ID,                   "PID_ADLINK_PROCESS_ID" },
  { PID_ADLINK_SERVICE_TYPE,                 "PID_ADLINK_SERVICE_TYPE" },
  { PID_ADLINK_ENTITY_FACTORY,               "PID_ADLINK_ENTITY_FACTORY" },
  { PID_ADLINK_WATCHDOG_SCHEDULING,          "PID_ADLINK_WATCHDOG_SCHEDULING" },
  { PID_ADLINK_LISTENER_SCHEDULING,          "PID_ADLINK_LISTENER_SCHEDULING" },
  { PID_ADLINK_SUBSCRIPTION_KEYS,            "PID_ADLINK_SUBSCRIPTION_KEYS" },
  { PID_ADLINK_READER_LIFESPAN,              "PID_ADLINK_READER_LIFESPAN" },
  { PID_ADLINK_SHARE,                        "PID_ADLINK_SHARE" },
  { PID_ADLINK_TYPE_DESCRIPTION,             "PID_ADLINK_TYPE_DESCRIPTION" },
  { PID_ADLINK_LAN_ID,                       "PID_ADLINK_LAN_ID" },
  { PID_ADLINK_ENDPOINT_GID,                 "PID_ADLINK_ENDPOINT_GID" },
  { PID_ADLINK_GROUP_GID,                    "PID_ADLINK_GROUP_GID" },
  { PID_ADLINK_EOTINFO,                      "PID_ADLINK_EOTINFO" },
  { PID_ADLINK_PART_CERT_NAME,               "PID_ADLINK_PART_CERT_NAME" },
  { PID_ADLINK_LAN_CERT_NAME,                "PID_ADLINK_LAN_CERT_NAME" },
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
  { ENCAPSULATION_CDR2_BE,              "CDR2_BE" },
  { ENCAPSULATION_CDR2_LE,              "CDR2_LE" },
  { ENCAPSULATION_D_CDR2_BE,            "D_CDR2_BE" },
  { ENCAPSULATION_D_CDR2_LE,            "D_CDR2_LE" },
  { ENCAPSULATION_PL_CDR2_BE,           "PL_CDR2_BE" },
  { ENCAPSULATION_PL_CDR2_LE,           "PL_CDR2_LE" },
  { ENCAPSULATION_SHMEM_REF_PLAIN,      "SHMEM_REF_PLAIN" },
  { ENCAPSULATION_SHMEM_REF_FLAT_DATA,  "SHMEM_REF_PLAIN" },
  { 0, NULL }
};

static const value_string data_representation_kind_vals[] = {
  { 0, "XCDR_DATA_REPRESENTATION" },
  { 1, "XML_DATA_REPRESENTATION" },
  { 2, "XCDR2_DATA_REPRESENTATION" },
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

static const value_string secure_transformation_kind[] = {
  { CRYPTO_TRANSFORMATION_KIND_NONE,          "NONE" },
  { CRYPTO_TRANSFORMATION_KIND_AES128_GMAC,   "AES128_GMAC" },
  { CRYPTO_TRANSFORMATION_KIND_AES128_GCM,    "AES128_GCM" },
  { CRYPTO_TRANSFORMATION_KIND_AES256_GMAC,   "AES256_GMAC" },
  { CRYPTO_TRANSFORMATION_KIND_AES256_GCM,    "AES256_GCM" },
  { 0, NULL }
};

static const value_string participant_message_data_kind [] = {
  { PARTICIPANT_MESSAGE_DATA_KIND_UNKNOWN,      "PARTICIPANT_MESSAGE_DATA_KIND_UNKNOWN" },
  { PARTICIPANT_MESSAGE_DATA_KIND_AUTOMATIC_LIVELINESS_UPDATE,  "PARTICIPANT_MESSAGE_DATA_KIND_AUTOMATIC_LIVELINESS_UPDATE" },
  { PARTICIPANT_MESSAGE_DATA_KIND_MANUAL_LIVELINESS_UPDATE,     "PARTICIPANT_MESSAGE_DATA_KIND_MANUAL_LIVELINESS_UPDATE" },
  { 0, NULL }
};

/* Vendor specific: RTI */
static const value_string type_consistency_kind_vals[] = {
  { DISALLOW_TYPE_COERCION,             "DISALLOW_TYPE_COERCION" },
  { ALLOW_TYPE_COERCION,                "ALLOW_TYPE_COERCION" },
  { 0, NULL }
};

static const value_string service_request_kind[] = {
  { RTI_SERVICE_REQUEST_ID_UNKNOWN,                 "RTI_SERVICE_REQUEST_ID_UNKNOWN" },
  { RTI_SERVICE_REQUEST_ID_TOPIC_QUERY,             "RTI_SERVICE_REQUEST_ID_TOPIC_QUERY" },
  { RTI_SERVICE_REQUEST_ID_LOCATOR_REACHABILITY,    "RTI_SERVICE_REQUEST_ID_LOCATOR_REACHABILITY" },
  { 0, NULL }
};
/* Vendor specific: RTI */
static const value_string acknowledgement_kind_vals[] = {
  { PROTOCOL_ACKNOWLEDGMENT,              "PROTOCOL_ACKNOWLEDGMENT" },
  { APPLICATION_AUTO_ACKNOWLEDGMENT,      "APPLICATION_AUTO_ACKNOWLEDGMENT" },
  { APPLICATION_ORDERED_ACKNOWLEDGMENT,   "APPLICATION_ORDERED_ACKNOWLEDGMENT" },
  { APPLICATION_EXPLICIT_ACKNOWLEDGMENT,  "APPLICATION_EXPLICIT_ACKNOWLEDGMENT" },
  { 0, NULL }
};

static const value_string security_symmetric_cipher_bit_vals[] = {
  { SECURITY_SYMMETRIC_CIPHER_BIT_AES128_GCM, "AES128_GCM"},
  { SECURITY_SYMMETRIC_CIPHER_BIT_AES256_GCM, "AES256_GCM"},
  { SECURITY_SYMMETRIC_CIPHER_BIT_CUSTOM_ALGORITHM, "Custom Algorithm"},
  {0, NULL}
};

static const value_string security_digital_signature_bit_vals[] = {
  { SECURITY_DIGITAL_SIGNATURE_BIT_RSASSAPSSMGF1SHA256_2048_SHA256, "RSASSAPSSMGF1SHA256_2048_SHA256"},
  { SECURITY_DIGITAL_SIGNATURE_BIT_RSASSAPKCS1V15_2048_SHA256,      "RSASSAPKCS1V15_2048_SHA256"},
  { SECURITY_DIGITAL_SIGNATURE_BIT_ECDSA_P256_SHA256,               "ECDSA_P256_SHA256"},
  { SECURITY_DIGITAL_SIGNATURE_BIT_ECDSA_P384_SHA384,               "ECDSA_P384_SHA384"},
  { SECURITY_DIGITAL_SIGNATURE_BIT_CUSTOM_ALGORITHM,                "Custom Algorithm"},
  { 0, NULL}
};

static const value_string security_key_establishment_bit_vals[] = {
  { SECURITY_KEY_ESTABLISHMENT_BIT_DHE_MODP2048256, "DHE_MODP2048256" },
  { SECURITY_KEY_ESTABLISHMENT_BIT_ECDHECEUM_P256, "ECDHECEUM_P256" },
  { SECURITY_KEY_ESTABLISHMENT_BIT_ECDHECEUM_P384, "ECDHECEUM_P384" },
  { SECURITY_KEY_ESTABLISHMENT_BIT_CUSTOM_ALGORITHM, "Custom Algorithm" },
  { 0, NULL}
};


static int* const TYPE_FLAG_FLAGS[] = {
  &hf_rtps_flag_typeflag_nested,                /* Bit 2 */
  &hf_rtps_flag_typeflag_mutable,               /* Bit 1 */
  &hf_rtps_flag_typeflag_final,                 /* Bit 0 */
  NULL
};

static int* const MEMBER_FLAGS[] = {
  &hf_rtps_flag_memberflag_union_default,       /* Bit 3 */
  &hf_rtps_flag_memberflag_shareable,           /* Bit 2 */
  &hf_rtps_flag_memberflag_optional,            /* Bit 1 */
  &hf_rtps_flag_memberflag_key,                 /* Bit 0 */
  NULL
};

static int* const UDPV4_WAN_LOCATOR_FLAGS[] = {
  &hf_rtps_flag_reserved80,                     /* Bit 7 */
  &hf_rtps_flag_reserved40,                     /* Bit 6 */
  &hf_rtps_flag_reserved20,                     /* Bit 5 */
  &hf_rtps_flag_reserved10,                     /* Bit 4 */
  &hf_rtps_flag_udpv4_wan_locator_r,       /* Bit 3 */
  &hf_rtps_flag_udpv4_wan_locator_b,       /* Bit 2 */
  &hf_rtps_flag_udpv4_wan_locator_p,       /* Bit 1 */
  &hf_rtps_flag_udpv4_wan_locator_u,       /* Bit 0 */
  NULL
};

static int* const UDPV4_WAN_BINDING_PING_FLAGS[] = {
  &hf_rtps_flag_reserved80,                     /* Bit 7 */
  &hf_rtps_flag_reserved40,                     /* Bit 6 */
  &hf_rtps_flag_reserved20,                     /* Bit 5 */
  &hf_rtps_flag_reserved10,                     /* Bit 4 */
  &hf_rtps_flag_reserved08,                     /* Bit 3 */
  &hf_rtps_flag_udpv4_wan_binding_ping_b,       /* Bit 2 */
  &hf_rtps_flag_udpv4_wan_binding_ping_l,       /* Bit 1 */
  &hf_rtps_flag_udpv4_wan_binding_ping_e,       /* Bit 0 */
  NULL
};

/* Vendor specific: RTI */
static const value_string ndds_transport_class_id_vals[] = {
  { NDDS_TRANSPORT_CLASSID_ANY,           "ANY" },
  { NDDS_TRANSPORT_CLASSID_UDPv4,         "UDPv4" },
  { NDDS_TRANSPORT_CLASSID_SHMEM,         "SHMEM" },
  { NDDS_TRANSPORT_CLASSID_INTRA,         "INTRA" },
  { NDDS_TRANSPORT_CLASSID_UDPv6,         "UDPv6" },
  { NDDS_TRANSPORT_CLASSID_DTLS,          "DTLS" },
  { NDDS_TRANSPORT_CLASSID_WAN,           "WAN" },
  { NDDS_TRANSPORT_CLASSID_TCPV4_LAN,     "TCPv4_LAN" },
  { NDDS_TRANSPORT_CLASSID_TCPV4_WAN,     "TCPv4_WAN" },
  { NDDS_TRANSPORT_CLASSID_TLSV4_LAN,     "TLSv4_LAN" },
  { NDDS_TRANSPORT_CLASSID_TLSV4_WAN,     "TLSv4_WAN" },
  { NDDS_TRANSPORT_CLASSID_PCIE,          "PCIE" },
  { NDDS_TRANSPORT_CLASSID_ITP,           "ITP" },
  { NDDS_TRANSPORT_CLASSID_UDPv4_WAN,     "UDPv4_WAN" },
  { 0, NULL }
};

static const value_string class_id_enum_names[] = {
  { RTI_OSAPI_COMPRESSION_CLASS_ID_NONE,  "NONE" },
  { RTI_OSAPI_COMPRESSION_CLASS_ID_ZLIB,  "ZLIB" },
  { RTI_OSAPI_COMPRESSION_CLASS_ID_BZIP2, "BZIP2" },
  { RTI_OSAPI_COMPRESSION_CLASS_ID_AUTO,  "AUTO"},
  { 0, NULL}
};

static int* const PAD_FLAGS[] = {
  &hf_rtps_flag_reserved80,                     /* Bit 7 */
  &hf_rtps_flag_reserved40,                     /* Bit 6 */
  &hf_rtps_flag_reserved20,                     /* Bit 5 */
  &hf_rtps_flag_reserved10,                     /* Bit 4 */
  &hf_rtps_flag_reserved08,                     /* Bit 3 */
  &hf_rtps_flag_reserved04,                     /* Bit 2 */
  &hf_rtps_flag_reserved02,                     /* Bit 1 */
  &hf_rtps_flag_endianness,                     /* Bit 0 */
  NULL
};

static int* const DATA_FLAGSv1[] = {
  &hf_rtps_flag_reserved80,                     /* Bit 7 */
  &hf_rtps_flag_reserved40,                     /* Bit 6 */
  &hf_rtps_flag_unregister,                     /* Bit 5 */
  &hf_rtps_flag_inline_qos_v1,                  /* Bit 4 */
  &hf_rtps_flag_hash_key,                       /* Bit 3 */
  &hf_rtps_flag_alive,                          /* Bit 2 */
  &hf_rtps_flag_data_present_v1,                /* Bit 1 */
  &hf_rtps_flag_endianness,                     /* Bit 0 */
  NULL
};

static int* const DATA_FLAGSv2[] = {
  &hf_rtps_flag_reserved80,                     /* Bit 7 */
  &hf_rtps_flag_reserved40,                     /* Bit 6 */
  &hf_rtps_flag_reserved20,                     /* Bit 5 */
  &hf_rtps_flag_status_info,                    /* Bit 4 */
  &hf_rtps_flag_hash_key,                       /* Bit 3 */
  &hf_rtps_flag_data_present_v2,                /* Bit 2 */
  &hf_rtps_flag_inline_qos_v2,                  /* Bit 1 */
  &hf_rtps_flag_endianness,                     /* Bit 0 */
  NULL
};

static int* const NOKEY_DATA_FRAG_FLAGS[] = {
  &hf_rtps_flag_reserved80,                     /* Bit 7 */
  &hf_rtps_flag_reserved40,                     /* Bit 6 */
  &hf_rtps_flag_reserved20,                     /* Bit 5 */
  &hf_rtps_flag_reserved10,                     /* Bit 4 */
  &hf_rtps_flag_reserved08,                     /* Bit 3 */
  &hf_rtps_flag_reserved04,                     /* Bit 2 */
  &hf_rtps_flag_inline_qos_v2,                  /* Bit 1 */
  &hf_rtps_flag_endianness,                     /* Bit 0 */
  NULL
};

static int* const NOKEY_DATA_FLAGS[] = {
  &hf_rtps_flag_reserved80,                     /* Bit 7 */
  &hf_rtps_flag_reserved40,                     /* Bit 6 */
  &hf_rtps_flag_reserved20,                     /* Bit 5 */
  &hf_rtps_flag_reserved10,                     /* Bit 4 */
  &hf_rtps_flag_reserved08,                     /* Bit 3 */
  &hf_rtps_flag_reserved04,                     /* Bit 2 */
  &hf_rtps_flag_inline_qos_v2,                  /* Bit 1 */
  &hf_rtps_flag_endianness,                     /* Bit 0 */
  NULL
};

static int* const ACKNACK_FLAGS[] = {
  &hf_rtps_flag_reserved80,                     /* Bit 7 */
  &hf_rtps_flag_reserved40,                     /* Bit 6 */
  &hf_rtps_flag_reserved20,                     /* Bit 5 */
  &hf_rtps_flag_reserved10,                     /* Bit 4 */
  &hf_rtps_flag_reserved08,                     /* Bit 3 */
  &hf_rtps_flag_reserved04,                     /* Bit 2 */
  &hf_rtps_flag_final,                          /* Bit 1 */
  &hf_rtps_flag_endianness,                     /* Bit 0 */
  NULL
};

static int* const NACK_FRAG_FLAGS[] = {
  &hf_rtps_flag_reserved80,                     /* Bit 7 */
  &hf_rtps_flag_reserved40,                     /* Bit 6 */
  &hf_rtps_flag_reserved20,                     /* Bit 5 */
  &hf_rtps_flag_reserved10,                     /* Bit 4 */
  &hf_rtps_flag_reserved08,                     /* Bit 3 */
  &hf_rtps_flag_reserved04,                     /* Bit 2 */
  &hf_rtps_flag_reserved02,                     /* Bit 1 */
  &hf_rtps_flag_endianness,                     /* Bit 0 */
  NULL
};

static int* const GAP_FLAGS[] = {
  &hf_rtps_flag_reserved80,                     /* Bit 7 */
  &hf_rtps_flag_reserved40,                     /* Bit 6 */
  &hf_rtps_flag_reserved20,                     /* Bit 5 */
  &hf_rtps_flag_reserved10,                     /* Bit 4 */
  &hf_rtps_flag_reserved08,                     /* Bit 3 */
  &hf_rtps_flag_reserved04,                     /* Bit 2 */
  &hf_rtps_flag_reserved02,                     /* Bit 1 */
  &hf_rtps_flag_endianness,                     /* Bit 0 */
  NULL
};

static int* const HEARTBEAT_FLAGS[] = {
  &hf_rtps_flag_reserved80,                     /* Bit 7 */
  &hf_rtps_flag_reserved40,                     /* Bit 6 */
  &hf_rtps_flag_reserved20,                     /* Bit 5 */
  &hf_rtps_flag_reserved10,                     /* Bit 4 */
  &hf_rtps_flag_reserved08,                     /* Bit 3 */
  &hf_rtps_flag_liveliness,                     /* Bit 2 */
  &hf_rtps_flag_final,                          /* Bit 1 */
  &hf_rtps_flag_endianness,                     /* Bit 0 */
  NULL
};

static int* const HEARTBEAT_BATCH_FLAGS[] = {
  &hf_rtps_flag_reserved80,                     /* Bit 7 */
  &hf_rtps_flag_reserved40,                     /* Bit 6 */
  &hf_rtps_flag_reserved20,                     /* Bit 5 */
  &hf_rtps_flag_reserved10,                     /* Bit 4 */
  &hf_rtps_flag_reserved08,                     /* Bit 3 */
  &hf_rtps_flag_liveliness,                     /* Bit 2 */
  &hf_rtps_flag_final,                          /* Bit 1 */
  &hf_rtps_flag_endianness,                     /* Bit 0 */
  NULL
};

static int* const HEARTBEAT_FRAG_FLAGS[] = {
  &hf_rtps_flag_reserved80,                     /* Bit 7 */
  &hf_rtps_flag_reserved40,                     /* Bit 6 */
  &hf_rtps_flag_reserved20,                     /* Bit 5 */
  &hf_rtps_flag_reserved10,                     /* Bit 4 */
  &hf_rtps_flag_reserved08,                     /* Bit 3 */
  &hf_rtps_flag_reserved04,                     /* Bit 2 */
  &hf_rtps_flag_reserved02,                     /* Bit 1 */
  &hf_rtps_flag_endianness,                     /* Bit 0 */
  NULL
};

static int* const RTPS_DATA_FLAGS[] = {
  &hf_rtps_flag_reserved80,                     /* Bit 7 */
  &hf_rtps_flag_reserved40,                     /* Bit 6 */
  &hf_rtps_flag_reserved20,                     /* Bit 5 */
  &hf_rtps_flag_reserved10,                     /* Bit 4 */
  &hf_rtps_flag_data_serialized_key,            /* Bit 3 */
  &hf_rtps_flag_data_present_v2,                /* Bit 2 */
  &hf_rtps_flag_inline_qos_v2,                  /* Bit 1 */
  &hf_rtps_flag_endianness,                     /* Bit 0 */
  NULL
};

static int* const RTPS_DATA_FRAG_FLAGS[] = {
  &hf_rtps_flag_reserved80,                     /* Bit 7 */
  &hf_rtps_flag_reserved40,                     /* Bit 6 */
  &hf_rtps_flag_reserved20,                     /* Bit 5 */
  &hf_rtps_flag_reserved10,                     /* Bit 4 */
  &hf_rtps_flag_reserved08,                     /* Bit 3 */
  &hf_rtps_flag_data_frag_serialized_key,       /* Bit 2 */
  &hf_rtps_flag_inline_qos_v2,                  /* Bit 1 */
  &hf_rtps_flag_endianness,                     /* Bit 0 */
  NULL
};

static int* const RTPS_DATA_BATCH_FLAGS[] = {
  &hf_rtps_flag_reserved80,                     /* Bit 7 */
  &hf_rtps_flag_reserved40,                     /* Bit 6 */
  &hf_rtps_flag_reserved20,                     /* Bit 5 */
  &hf_rtps_flag_reserved10,                     /* Bit 4 */
  &hf_rtps_flag_reserved08,                     /* Bit 3 */
  &hf_rtps_flag_reserved04,                     /* Bit 2 */
  &hf_rtps_flag_inline_qos_v2,                  /* Bit 1 */
  &hf_rtps_flag_endianness,                     /* Bit 0 */
  NULL
};

static int* const RTPS_SAMPLE_INFO_FLAGS16[] = {
  &hf_rtps_flag_reserved8000,                   /* Bit 15 */
  &hf_rtps_flag_reserved4000,                   /* Bit 14 */
  &hf_rtps_flag_reserved2000,                   /* Bit 13 */
  &hf_rtps_flag_reserved1000,                   /* Bit 12 */
  &hf_rtps_flag_reserved0800,                   /* Bit 11 */
  &hf_rtps_flag_reserved0400,                   /* Bit 10 */
  &hf_rtps_flag_reserved0200,                   /* Bit 9 */
  &hf_rtps_flag_reserved0100,                   /* Bit 8 */
  &hf_rtps_flag_reserved0080,                   /* Bit 7 */
  &hf_rtps_flag_reserved0040,                   /* Bit 6 */
  &hf_rtps_flag_serialize_key16,                /* Bit 5 */
  &hf_rtps_flag_invalid_sample,                 /* Bit 4 */
  &hf_rtps_flag_data_present16,                 /* Bit 3 */
  &hf_rtps_flag_offsetsn_present,               /* Bit 2 */
  &hf_rtps_flag_inline_qos16_v2,                /* Bit 1 */
  &hf_rtps_flag_timestamp_present,              /* Bit 0 */
  NULL
};

static int* const INFO_TS_FLAGS[] = {
  &hf_rtps_flag_reserved80,                     /* Bit 7 */
  &hf_rtps_flag_reserved40,                     /* Bit 6 */
  &hf_rtps_flag_reserved20,                     /* Bit 5 */
  &hf_rtps_flag_reserved10,                     /* Bit 4 */
  &hf_rtps_flag_reserved08,                     /* Bit 3 */
  &hf_rtps_flag_reserved04,                     /* Bit 2 */
  &hf_rtps_flag_timestamp,                      /* Bit 1 */
  &hf_rtps_flag_endianness,                     /* Bit 0 */
  NULL
};

static int* const INFO_SRC_FLAGS[] = {
  &hf_rtps_flag_reserved80,                     /* Bit 7 */
  &hf_rtps_flag_reserved40,                     /* Bit 6 */
  &hf_rtps_flag_reserved20,                     /* Bit 5 */
  &hf_rtps_flag_reserved10,                     /* Bit 4 */
  &hf_rtps_flag_reserved08,                     /* Bit 3 */
  &hf_rtps_flag_reserved04,                     /* Bit 2 */
  &hf_rtps_flag_reserved02,                     /* Bit 1 */
  &hf_rtps_flag_endianness,                     /* Bit 0 */
  NULL
};

static int* const INFO_REPLY_IP4_FLAGS[] = {
  &hf_rtps_flag_reserved80,                     /* Bit 7 */
  &hf_rtps_flag_reserved40,                     /* Bit 6 */
  &hf_rtps_flag_reserved20,                     /* Bit 5 */
  &hf_rtps_flag_reserved10,                     /* Bit 4 */
  &hf_rtps_flag_reserved08,                     /* Bit 3 */
  &hf_rtps_flag_reserved04,                     /* Bit 2 */
  &hf_rtps_flag_multicast,                      /* Bit 1 */
  &hf_rtps_flag_endianness,                     /* Bit 0 */
  NULL
};

static int* const INFO_DST_FLAGS[] = {
  &hf_rtps_flag_reserved80,                     /* Bit 7 */
  &hf_rtps_flag_reserved40,                     /* Bit 6 */
  &hf_rtps_flag_reserved20,                     /* Bit 5 */
  &hf_rtps_flag_reserved10,                     /* Bit 4 */
  &hf_rtps_flag_reserved08,                     /* Bit 3 */
  &hf_rtps_flag_reserved04,                     /* Bit 2 */
  &hf_rtps_flag_reserved02,                     /* Bit 1 */
  &hf_rtps_flag_endianness,                     /* Bit 0 */
  NULL
};

static int* const INFO_REPLY_FLAGS[] = {
  &hf_rtps_flag_reserved80,                     /* Bit 7 */
  &hf_rtps_flag_reserved40,                     /* Bit 6 */
  &hf_rtps_flag_reserved20,                     /* Bit 5 */
  &hf_rtps_flag_reserved10,                     /* Bit 4 */
  &hf_rtps_flag_reserved08,                     /* Bit 3 */
  &hf_rtps_flag_reserved04,                     /* Bit 2 */
  &hf_rtps_flag_multicast,                      /* Bit 1 */
  &hf_rtps_flag_endianness,                     /* Bit 0 */
  NULL
};

static int* const RTI_CRC_FLAGS[] = {
  &hf_rtps_flag_reserved80,                     /* Bit 7 */
  &hf_rtps_flag_reserved40,                     /* Bit 6 */
  &hf_rtps_flag_reserved20,                     /* Bit 5 */
  &hf_rtps_flag_reserved10,                     /* Bit 4 */
  &hf_rtps_flag_reserved08,                     /* Bit 3 */
  &hf_rtps_flag_reserved04,                     /* Bit 2 */
  &hf_rtps_flag_reserved02,                     /* Bit 1 */
  &hf_rtps_flag_endianness,                     /* Bit 0 */
  NULL
};
/* It is a 4 bytes field but with these 8 bits is enough */
static int* const STATUS_INFO_FLAGS[] = {
  &hf_rtps_flag_reserved80,                     /* Bit 7 */
  &hf_rtps_flag_reserved40,                     /* Bit 6 */
  &hf_rtps_flag_reserved20,                     /* Bit 5 */
  &hf_rtps_flag_reserved10,                     /* Bit 4 */
  &hf_rtps_flag_reserved08,                     /* Bit 3 */
  &hf_rtps_flag_reserved04,                     /* Bit 2 */
  &hf_rtps_flag_unregistered,                   /* Bit 1 */
  &hf_rtps_flag_disposed,                       /* Bit 0 */
  NULL
};

static int* const BUILTIN_ENDPOINT_FLAGS[] = {
  &hf_rtps_flag_participant_secure_reader,                      /* Bit 27 */
  &hf_rtps_flag_participant_secure_writer,                      /* Bit 26 */
  &hf_rtps_flag_secure_participant_volatile_message_reader,     /* Bit 25 */
  &hf_rtps_flag_secure_participant_volatile_message_writer,     /* Bit 24 */
  &hf_rtps_flag_participant_stateless_message_reader,           /* Bit 23 */
  &hf_rtps_flag_participant_stateless_message_writer,           /* Bit 22 */
  &hf_rtps_flag_secure_participant_message_reader,              /* Bit 21 */
  &hf_rtps_flag_secure_participant_message_writer,              /* Bit 20 */
  &hf_rtps_flag_secure_subscription_reader,                     /* Bit 19 */
  &hf_rtps_flag_secure_subscription_writer,                     /* Bit 18 */
  &hf_rtps_flag_secure_publication_reader,                      /* Bit 17 */
  &hf_rtps_flag_secure_publication_writer,                      /* Bit 16 */
  &hf_rtps_flag_builtin_endpoint_set_reserved,      /* Bit 12-15 */
  &hf_rtps_flag_participant_message_datareader,     /* Bit 11 */
  &hf_rtps_flag_participant_message_datawriter,     /* Bit 10 */
  &hf_rtps_flag_participant_state_detector,         /* Bit 9 */
  &hf_rtps_flag_participant_state_announcer,        /* Bit 8 */
  &hf_rtps_flag_participant_proxy_detector,         /* Bit 7 */
  &hf_rtps_flag_participant_proxy_announcer,        /* Bit 6 */
  &hf_rtps_flag_subscription_detector,              /* Bit 5 */
  &hf_rtps_flag_subscription_announcer,             /* Bit 4 */
  &hf_rtps_flag_publication_detector,               /* Bit 3 */
  &hf_rtps_flag_publication_announcer,              /* Bit 2 */
  &hf_rtps_flag_participant_detector,               /* Bit 1 */
  &hf_rtps_flag_participant_announcer,              /* Bit 0 */
  NULL
};

static int* const SECURE_FLAGS[] = {
  &hf_rtps_flag_reserved80,                     /* Bit 7 */
  &hf_rtps_flag_reserved40,                     /* Bit 6 */
  &hf_rtps_flag_reserved20,                     /* Bit 5 */
  &hf_rtps_flag_reserved10,                     /* Bit 4 */
  &hf_rtps_flag_reserved08,                     /* Bit 3 */
  &hf_rtps_flag_reserved04,                     /* Bit 2 */
  &hf_rtps_flag_multisubmessage,                /* Bit 1 */
  &hf_rtps_flag_endianness,                     /* Bit 0 */
  NULL
};

static int* const SECURE_PREFIX_FLAGS[] = {
  &hf_rtps_flag_reserved80,                     /* Bit 7 */
  &hf_rtps_flag_reserved40,                     /* Bit 6 */
  &hf_rtps_flag_reserved20,                     /* Bit 5 */
  &hf_rtps_flag_reserved10,                     /* Bit 4 */
  &hf_rtps_flag_reserved08,                     /* Bit 3 */
  &hf_rtps_flag_reserved04,                     /* Bit 2 */
  &hf_rtps_flag_reserved02,                     /* Bit 1 */
  &hf_rtps_flag_endianness,                     /* Bit 0 */
  NULL
};

static int* const SECURE_POSTFIX_FLAGS[] = {
  &hf_rtps_flag_reserved80,                     /* Bit 7 */
  &hf_rtps_flag_reserved40,                     /* Bit 6 */
  &hf_rtps_flag_reserved20,                     /* Bit 5 */
  &hf_rtps_flag_reserved10,                     /* Bit 4 */
  &hf_rtps_flag_reserved08,                     /* Bit 3 */
  &hf_rtps_flag_reserved04,                     /* Bit 2 */
  &hf_rtps_flag_reserved02,                     /* Bit 1 */
  &hf_rtps_flag_endianness,                     /* Bit 0 */
  NULL
};

static int* const ENDPOINT_SECURITY_INFO_FLAGS[] = {
  &hf_rtps_flag_endpoint_security_attribute_flag_is_valid,                      /* Bit 31 */
  &hf_rtps_flag_endpoint_security_attribute_flag_is_liveliness_protected,       /* Bit 6 */
  &hf_rtps_flag_endpoint_security_attribute_flag_is_key_protected,              /* Bit 5 */
  &hf_rtps_flag_endpoint_security_attribute_flag_is_payload_protected,          /* Bit 4 */
  &hf_rtps_flag_endpoint_security_attribute_flag_is_submessage_protected,       /* Bit 3 */
  &hf_rtps_flag_endpoint_security_attribute_flag_is_discovery_protected,        /* Bit 2 */
  &hf_rtps_flag_endpoint_security_attribute_flag_is_write_protected,            /* Bit 1 */
  &hf_rtps_flag_endpoint_security_attribute_flag_is_read_protected,             /* Bit 0 */
  NULL
};

static int* const PLUGIN_ENDPOINT_SECURITY_INFO_FLAGS[] = {
  &hf_rtps_flag_plugin_endpoint_security_attribute_flag_is_valid,                 /* Bit 31 */
  &hf_rtps_flag_plugin_endpoint_security_attribute_flag_is_liveliness_encrypted,  /* Bit 2 */
  &hf_rtps_flag_plugin_endpoint_security_attribute_flag_is_key_encrypted,         /* Bit 1 */
  &hf_rtps_flag_plugin_endpoint_security_attribute_flag_is_payload_encrypted,     /* Bit 0 */
  NULL
};
static int* const PARTICIPANT_SECURITY_INFO_FLAGS[] = {
  &hf_rtps_flag_participant_security_attribute_flag_is_valid,                     /* Bit 31 */
  &hf_rtps_flag_participant_security_attribute_flag_is_liveliness_protected,      /* Bit 2 */
  &hf_rtps_flag_participant_security_attribute_flag_is_discovery_protected,       /* Bit 1 */
  &hf_rtps_flag_participant_security_attribute_flag_is_rtps_protected,            /* Bit 0 */
  NULL
};

static int* const PLUGIN_PARTICIPANT_SECURITY_INFO_FLAGS[] = {
    &hf_rtps_flag_plugin_participant_security_attribute_flag_is_valid,                        /* Bit 31 */
    &hf_rtps_flag_plugin_participant_security_attribute_flag_is_liveliness_origin_encrypted,  /* Bit 5 */
    &hf_rtps_flag_plugin_participant_security_attribute_flag_is_discovery_origin_encrypted,   /* Bit 4 */
    &hf_rtps_flag_plugin_participant_security_attribute_flag_is_rtps_origin_encrypted,        /* Bit 3 */
    &hf_rtps_flag_plugin_participant_security_attribute_flag_is_liveliness_encrypted,         /* Bit 2 */
    &hf_rtps_flag_plugin_participant_security_attribute_flag_is_discovery_encrypted,          /* Bit 1 */
    &hf_rtps_flag_plugin_participant_security_attribute_flag_is_rtps_encrypted,               /* Bit 0 */
    NULL
};

/* Vendor specific: RTI */
static int* const APP_ACK_FLAGS[] = {
  &hf_rtps_flag_reserved80,                     /* Bit 7 */
  &hf_rtps_flag_reserved40,                     /* Bit 6 */
  &hf_rtps_flag_reserved20,                     /* Bit 5 */
  &hf_rtps_flag_reserved10,                     /* Bit 4 */
  &hf_rtps_flag_reserved08,                     /* Bit 3 */
  &hf_rtps_flag_reserved04,                     /* Bit 2 */
  &hf_rtps_flag_reserved02,                     /* Bit 1 */
  &hf_rtps_flag_endianness,                     /* Bit 0 */
  NULL
};
/* Vendor specific: RTI */
static int* const APP_ACK_CONF_FLAGS[] = {
  &hf_rtps_flag_reserved80,                     /* Bit 7 */
  &hf_rtps_flag_reserved40,                     /* Bit 6 */
  &hf_rtps_flag_reserved20,                     /* Bit 5 */
  &hf_rtps_flag_reserved10,                     /* Bit 4 */
  &hf_rtps_flag_reserved08,                     /* Bit 3 */
  &hf_rtps_flag_reserved04,                     /* Bit 2 */
  &hf_rtps_flag_reserved02,                     /* Bit 1 */
  &hf_rtps_flag_endianness,                     /* Bit 0 */
  NULL
};
/* Vendor specific: RTI */
static int* const HEARTBEAT_VIRTUAL_FLAGS[] = {
  &hf_rtps_flag_reserved80,                     /* Bit 7 */
  &hf_rtps_flag_reserved40,                     /* Bit 6 */
  &hf_rtps_flag_reserved20,                     /* Bit 5 */
  &hf_rtps_flag_reserved10,                     /* Bit 4 */
  &hf_rtps_flag_no_virtual_guids,               /* Bit 3 */
  &hf_rtps_flag_multiple_writers,               /* Bit 2 */
  &hf_rtps_flag_multiple_virtual_guids,         /* Bit 1 */
  &hf_rtps_flag_endianness,                     /* Bit 0 */
  NULL
};
/* Vendor specific: RTI */
static int* const DATA_FRAG_FLAGS[] = {
  &hf_rtps_flag_reserved80,                     /* Bit 7 */
  &hf_rtps_flag_reserved40,                     /* Bit 6 */
  &hf_rtps_flag_reserved20,                     /* Bit 5 */
  &hf_rtps_flag_reserved10,                     /* Bit 4 */
  &hf_rtps_flag_reserved08,                     /* Bit 3 */
  &hf_rtps_flag_hash_key_rti,                   /* Bit 2 */
  &hf_rtps_flag_inline_qos_v2,                  /* Bit 1 */
  &hf_rtps_flag_endianness,                     /* Bit 0 */
  NULL
};
#if 0
/* Vendor specific: RTI */
static int* const NACK_FLAGS[] = {
  &hf_rtps_flag_reserved80,                     /* Bit 7 */
  &hf_rtps_flag_reserved40,                     /* Bit 6 */
  &hf_rtps_flag_reserved20,                     /* Bit 5 */
  &hf_rtps_flag_reserved10,                     /* Bit 4 */
  &hf_rtps_flag_reserved08,                     /* Bit 3 */
  &hf_rtps_flag_reserved04,                     /* Bit 2 */
  &hf_rtps_flag_final,                          /* Bit 1 */
  &hf_rtps_flag_endianness,                     /* Bit 0 */
  NULL
};
#endif

static int* const VENDOR_BUILTIN_ENDPOINT_FLAGS[] = {
  &hf_rtps_flag_cloud_discovery_service_announcer,    /* Bit 6 */
  &hf_rtps_flag_secure_service_request_reader,        /* Bit 5 */
  &hf_rtps_flag_secure_service_request_writer,        /* Bit 4 */
  &hf_rtps_flag_locator_ping_reader,                  /* Bit 3 */
  &hf_rtps_flag_locator_ping_writer,                  /* Bit 2 */
  &hf_rtps_flag_service_request_reader,               /* Bit 1 */
  &hf_rtps_flag_service_request_writer,               /* Bit 0 */
  NULL
};

static int* const ENDPOINT_SECURITY_ATTRIBUTES[] = {
  &hf_rtps_flag_security_payload_protected,            /* Bit 3 */
  &hf_rtps_flag_security_submessage_protected,         /* Bit 2 */
  &hf_rtps_flag_security_discovery_protected,          /* Bit 1 */
  &hf_rtps_flag_security_access_protected,             /* Bit 0 */
  NULL
};


static int* const SECURITY_SIMMETRIC_CIPHER_MASK_FLAGS[] = {
  &hf_rtps_flag_security_symmetric_cipher_mask_custom_algorithm,
  &hf_rtps_flag_security_symmetric_cipher_mask_aes256_gcm,
  &hf_rtps_flag_security_symmetric_cipher_mask_aes128_gcm,
  NULL
};

static int* const SECURITY_KEY_ESTABLISHMENT_MASK_FLAGS[] = {
  &hf_rtps_flag_security_key_establishment_mask_custom_algorithm,
  &hf_rtps_flag_security_key_establishment_mask_ecdheceum_p384,
  &hf_rtps_flag_security_key_establishment_mask_ecdheceum_p256,
  &hf_rtps_flag_security_key_establishment_mask_dhe_modp2048256,
  NULL
};

static int* const SECURITY_DIGITAL_SIGNATURE_MASK_FLAGS[] = {
  &hf_rtps_flag_security_digital_signature_mask_custom_algorithm,
  &hf_rtps_flag_security_digital_signature_mask_ecdsa_p384_sha384,
  &hf_rtps_flag_security_digital_signature_mask_ecdsa_p256_sha256,
  &hf_rtps_flag_security_digital_signature_mask_rsassapkcs1v15_2048_sha256,
  &hf_rtps_flag_security_digital_signature_mask_rsassapssmgf1sha256_2048_sha256,
  NULL
};


/**TCP get DomainId feature constants**/
#define RTPS_UNKNOWN_DOMAIN_ID_VAL -1
#define RTPS_UNKNOWN_DOMAIN_ID_STR "Unknown"
#define RTPS_UNKNOWN_DOMAIN_ID_STR_LEN sizeof(RTPS_UNKNOWN_DOMAIN_ID_STR)
#define RTPS_TCPMAP_DOMAIN_ID_KEY_STR "ParticipantGuid"
#define RTPS_TCPMAP_DOMAIN_ID_PROTODATA_KEY 0

/* End of TCP get DomainId feature constants */

typedef struct _participant_info {
  gint domainId;
} participant_info;

typedef struct _datawriter_qos {
  guint32 reliability_kind;
  guint32 durability_kind;
  guint32 ownership_kind;
} datawriter_qos;

#define MAX_TOPIC_AND_TYPE_LENGTH 256
typedef struct _type_mapping {
  endpoint_guid guid;
  gchar type_name[MAX_TOPIC_AND_TYPE_LENGTH];
  gchar topic_name[MAX_TOPIC_AND_TYPE_LENGTH];
  gint fields_visited;
  datawriter_qos dw_qos;
  guint32 dcps_publication_frame_number;
  guint64 type_id;
} type_mapping;

/* Links a coherent set with an specific writer. Useful to detect if an empty packet is the end of a coherent set */
typedef struct _coherent_set_entity_info {
  endpoint_guid guid;
  guint64 writer_seq_number;
  guint64 coherent_set_seq_number;
  guint64 expected_coherent_set_end_writers_seq_number;
} coherent_set_entity_info;

typedef struct _coherent_set_key {
  endpoint_guid guid;
  guint64 coherent_set_seq_number;
} coherent_set_key;

/* Holds information about the coherent set */
typedef struct _coherent_set_info {
  coherent_set_key *key;
  guint64 writer_seq_number;
  gboolean is_set;
} coherent_set_info;

/* Links a writer_seq_number with a coherent set. Useful when cohrent set ends with paramter empty packet*/
typedef struct _coherent_set_end {
  guint64 writer_seq_number;
  coherent_set_key coherent_set_id;
} coherent_set_end;

typedef struct _coherent_set_track {
  wmem_map_t *entities_using_map;
  wmem_map_t *coherent_set_registry_map;
} coherent_set_track;

static coherent_set_track coherent_set_tracking;
static wmem_map_t * registry = NULL;
static reassembly_table rtps_reassembly_table;
static wmem_map_t *discovered_tcp_participants;

static const fragment_items rtps_frag_items = {
    &ett_rtps_fragment,
    &ett_rtps_fragments,
    &hf_rtps_fragments,
    &hf_rtps_fragment,
    &hf_rtps_fragment_overlap,
    &hf_rtps_fragment_overlap_conflict,
    &hf_rtps_fragment_multiple_tails,
    &hf_rtps_fragment_too_long_fragment,
    &hf_rtps_fragment_error,
    &hf_rtps_fragment_count,
    &hf_rtps_reassembled_in,
    &hf_rtps_reassembled_length,
    &hf_rtps_reassembled_data,
    "RTPS fragments"
};

static void rtps_util_dissect_parameter_header(tvbuff_t * tvb, gint * offset,
        const guint encoding, guint32 * member_id, guint32 * member_length) {
  *member_id = tvb_get_guint16(tvb, *offset, encoding);
  *offset += 2;
  *member_length = tvb_get_guint16(tvb, *offset, encoding);
  *offset += 2;

  if ((*member_id & PID_EXTENDED) == PID_EXTENDED) {
    /* get extended member id and length */
    *member_id = tvb_get_guint32(tvb, *offset, encoding);
    *offset += 4;
    *member_length = tvb_get_guint32(tvb, *offset, encoding);
    *offset += 4;
  }
}

static gint dissect_mutable_member(proto_tree *tree , tvbuff_t * tvb, gint offset, guint encoding, guint encoding_version,
        dissection_info * info, gboolean * is_end, gboolean show);

static gint get_native_type_cdr_length(guint64 member_kind) {
  guint length = 0;

  switch (member_kind) {
      case RTI_CDR_TYPE_OBJECT_TYPE_KIND_BOOLEAN_TYPE: {
          length = 1;
          break;
      }
      case RTI_CDR_TYPE_OBJECT_TYPE_KIND_CHAR_8_TYPE:
      case RTI_CDR_TYPE_OBJECT_TYPE_KIND_BYTE_TYPE: {
          length = 1;
          break;
      }
      case RTI_CDR_TYPE_OBJECT_TYPE_KIND_INT_16_TYPE: {
          length = 2;
          break;
      }
      case RTI_CDR_TYPE_OBJECT_TYPE_KIND_UINT_16_TYPE: {
          length = 2;
          break;
      }
      case RTI_CDR_TYPE_OBJECT_TYPE_KIND_ENUMERATION_TYPE:
      case RTI_CDR_TYPE_OBJECT_TYPE_KIND_INT_32_TYPE: {
          length = 4;
          break;
      }
      case RTI_CDR_TYPE_OBJECT_TYPE_KIND_UINT_32_TYPE: {
          length = 4;
          break;
      }
      case RTI_CDR_TYPE_OBJECT_TYPE_KIND_INT_64_TYPE: {
          length = 8;
          break;
      }
      case RTI_CDR_TYPE_OBJECT_TYPE_KIND_UINT_64_TYPE: {
          length = 8;
          break;
      }
      case RTI_CDR_TYPE_OBJECT_TYPE_KIND_FLOAT_32_TYPE: {
          length = 4;
          break;
      }
      case RTI_CDR_TYPE_OBJECT_TYPE_KIND_FLOAT_64_TYPE: {
          length = 8;
          break;
      }
      case RTI_CDR_TYPE_OBJECT_TYPE_KIND_FLOAT_128_TYPE: {
          length = 16;
          break;
      }
      default: {
          length = -1;
          break;
      }
  }
  return length;
}

static gint get_native_type_cdr_alignment(guint64 member_kind, gint encapsulation_version) {
  guint align = 0;

  switch (member_kind) {
  case RTI_CDR_TYPE_OBJECT_TYPE_KIND_BOOLEAN_TYPE: {
    align = 1;
    break;
  }
  case RTI_CDR_TYPE_OBJECT_TYPE_KIND_CHAR_8_TYPE:
  case RTI_CDR_TYPE_OBJECT_TYPE_KIND_BYTE_TYPE: {
    align = 1;
    break;
  }
  case RTI_CDR_TYPE_OBJECT_TYPE_KIND_INT_16_TYPE: {
    align = 2;
    break;
  }
  case RTI_CDR_TYPE_OBJECT_TYPE_KIND_UINT_16_TYPE: {
    align = 2;
    break;
  }
  case RTI_CDR_TYPE_OBJECT_TYPE_KIND_ENUMERATION_TYPE:
  case RTI_CDR_TYPE_OBJECT_TYPE_KIND_INT_32_TYPE: {
    align = 4;
    break;
  }
  case RTI_CDR_TYPE_OBJECT_TYPE_KIND_UINT_32_TYPE: {
    align = 4;
    break;
  }
  case RTI_CDR_TYPE_OBJECT_TYPE_KIND_INT_64_TYPE: {
    align = (encapsulation_version == 1) ? 8 : 4;
    break;
  }
  case RTI_CDR_TYPE_OBJECT_TYPE_KIND_UINT_64_TYPE: {
    align = (encapsulation_version == 1) ? 8 : 4;
    break;
  }
  case RTI_CDR_TYPE_OBJECT_TYPE_KIND_FLOAT_32_TYPE: {
    align = 4;
    break;
  }
  case RTI_CDR_TYPE_OBJECT_TYPE_KIND_FLOAT_64_TYPE: {
    align = (encapsulation_version == 1) ? 8 : 4;
    break;
  }
  case RTI_CDR_TYPE_OBJECT_TYPE_KIND_FLOAT_128_TYPE: {
    align = (encapsulation_version == 1) ? 8 : 4;
    break;
  }
  default: {
    align = -1;
    break;
  }
  }
  return align;
}

static gint get_encapsulation_endianness(gint encapsulation_id)
{
  return (encapsulation_id == ENCAPSULATION_CDR_LE ||
          encapsulation_id == ENCAPSULATION_PL_CDR_LE ||
          encapsulation_id == ENCAPSULATION_CDR2_LE ||
          encapsulation_id == ENCAPSULATION_D_CDR2_LE ||
          encapsulation_id == ENCAPSULATION_PL_CDR2_LE) ? ENC_LITTLE_ENDIAN : ENC_BIG_ENDIAN;
}

static gint get_encapsulation_version(gint encapsulation_id)
{
  return (encapsulation_id == ENCAPSULATION_CDR2_LE ||
    encapsulation_id == ENCAPSULATION_D_CDR2_LE ||
    encapsulation_id == ENCAPSULATION_PL_CDR2_LE) ? 2 : 1;
}

/* this is a recursive function. _info may or may not be NULL depending on the use iteration */
static gint dissect_user_defined(proto_tree *tree, tvbuff_t * tvb, gint offset, guint encoding, guint encoding_version,
        dissection_info * _info, guint64 type_id, gchar * name,
        RTICdrTypeObjectExtensibility extensibility, gint offset_zero,
        guint16 flags, guint32 element_member_id, gboolean show) {

    guint64 member_kind;
    dissection_info * info = NULL;
    guint32 member_id;
    guint32 member_length = 0;

    if (_info)  { /* first call enters here */
        info = _info;
        member_kind = info->member_kind;
    } else {
        info = (dissection_info *) wmem_map_lookup(dissection_infos, &(type_id));
        if (info != NULL) {
            member_kind = info->member_kind;
        } else {
            member_kind = type_id;
        }
    }
    if (info && (flags & MEMBER_OPTIONAL) == MEMBER_OPTIONAL) {
        gint offset_before = offset;
        rtps_util_dissect_parameter_header(tvb, &offset, encoding, &member_id, &member_length);
        offset = offset_before;
        if (element_member_id != 0 && member_id != element_member_id)
            return offset;
    }
    if (extensibility == EXTENSIBILITY_MUTABLE) {
      rtps_util_dissect_parameter_header(tvb, &offset, encoding, &member_id, &member_length);
      offset_zero = offset;
      if ((member_id & PID_LIST_END) == PID_LIST_END){
       /* If this is the end of the list, don't add a tree.
       * If we add more logic here in the future, take into account that
       * offset is incremented by 4 */
          offset += 0;
          return offset;
      }
      if (member_length == 0){
          return offset;
      }
    }
    //proto_item_append_text(tree, "(Before Switch 0x%016" PRIx64 ")", type_id);

    switch (member_kind) {
        case RTI_CDR_TYPE_OBJECT_TYPE_KIND_BOOLEAN_TYPE: {
            gint length = get_native_type_cdr_length(member_kind);
            if (show) {
                ALIGN_ZERO(offset, get_native_type_cdr_alignment(member_kind, encoding_version), offset_zero);
                gint16 value = tvb_get_gint8(tvb, offset);
                proto_tree_add_boolean_format(tree, hf_rtps_dissection_boolean, tvb, offset, length, value,
                  "%s: %d", name, value);
            }
            offset += length;
            break;
        }
        case RTI_CDR_TYPE_OBJECT_TYPE_KIND_CHAR_8_TYPE:
        case RTI_CDR_TYPE_OBJECT_TYPE_KIND_BYTE_TYPE: {
            gint length = get_native_type_cdr_length(member_kind);
            if (show) {
                ALIGN_ZERO(offset, get_native_type_cdr_alignment(member_kind, encoding_version), offset_zero);
                gint16 value = tvb_get_gint8(tvb, offset);
                proto_tree_add_uint_format(tree, hf_rtps_dissection_byte, tvb, offset, length, value,
                    "%s: %d", name, value);
            }
            offset += length;
            break;
        }
        case RTI_CDR_TYPE_OBJECT_TYPE_KIND_INT_16_TYPE: {
            gint length = get_native_type_cdr_length(member_kind);
            if (show) {
                ALIGN_ZERO(offset, get_native_type_cdr_alignment(member_kind, encoding_version), offset_zero);
                gint16 value = tvb_get_gint16(tvb, offset, encoding);
                proto_tree_add_int_format(tree, hf_rtps_dissection_int16, tvb, offset, length, value,
                  "%s: %d", name, value);
            }
            offset += length;
            break;
        }
        case RTI_CDR_TYPE_OBJECT_TYPE_KIND_UINT_16_TYPE: {
            gint length = get_native_type_cdr_length(member_kind);
            if (show) {
                ALIGN_ZERO(offset, get_native_type_cdr_alignment(member_kind, encoding_version), offset_zero);
                guint16 value = tvb_get_guint16(tvb, offset, encoding);
                proto_tree_add_uint_format(tree, hf_rtps_dissection_uint16, tvb, offset, length, value,
                  "%s: %u", name, value);
            }
            offset += length;
            break;
        }
        case RTI_CDR_TYPE_OBJECT_TYPE_KIND_ENUMERATION_TYPE:
        case RTI_CDR_TYPE_OBJECT_TYPE_KIND_INT_32_TYPE: {
            gint length = get_native_type_cdr_length(member_kind);
            if (show) {
                ALIGN_ZERO(offset, get_native_type_cdr_alignment(member_kind, encoding_version), offset_zero);
                gint value = tvb_get_gint32(tvb, offset, encoding);
                proto_tree_add_int_format(tree, hf_rtps_dissection_int32, tvb, offset, length, value,
                  "%s: %d", name, value);
            }
            offset += length;
            break;
        }
        case RTI_CDR_TYPE_OBJECT_TYPE_KIND_UINT_32_TYPE: {
            gint length = get_native_type_cdr_length(member_kind);
            if (show) {
                ALIGN_ZERO(offset, get_native_type_cdr_alignment(member_kind, encoding_version), offset_zero);
                guint value = tvb_get_guint32(tvb, offset, encoding);
                proto_tree_add_uint_format(tree, hf_rtps_dissection_uint32, tvb, offset, length, value,
                  "%s: %u", name, value);
            }
            offset += length;
            break;
        }
        case RTI_CDR_TYPE_OBJECT_TYPE_KIND_INT_64_TYPE: {
            gint length = get_native_type_cdr_length(member_kind);
            if (show) {
                ALIGN_ZERO(offset, get_native_type_cdr_alignment(member_kind, encoding_version), offset_zero);
                gint64 value = tvb_get_gint64(tvb, offset, encoding);
                proto_tree_add_int64_format(tree, hf_rtps_dissection_int64, tvb, offset, length, value,
                  "%s: %"PRId64, name, value);
            }
            offset += length;
            break;
        }
        case RTI_CDR_TYPE_OBJECT_TYPE_KIND_UINT_64_TYPE: {
            gint length = get_native_type_cdr_length(member_kind);
            if (show) {
                ALIGN_ZERO(offset, get_native_type_cdr_alignment(member_kind, encoding_version), offset_zero);
                guint64 value = tvb_get_guint64(tvb, offset, encoding);
                proto_tree_add_uint64_format(tree, hf_rtps_dissection_uint64, tvb, offset, length, value,
                  "%s: %"PRIu64, name, value);
            }
            offset += length;
            break;
        }
        case RTI_CDR_TYPE_OBJECT_TYPE_KIND_FLOAT_32_TYPE: {
            gint length = get_native_type_cdr_length(member_kind);
            if (show) {
                ALIGN_ZERO(offset, get_native_type_cdr_alignment(member_kind, encoding_version), offset_zero);
                gfloat value = tvb_get_ieee_float(tvb, offset, encoding);
                proto_tree_add_float_format(tree, hf_rtps_dissection_float, tvb, offset, length, value,
                  "%s: %.6f", name, value);
            }
            offset += length;
            break;
        }
        case RTI_CDR_TYPE_OBJECT_TYPE_KIND_FLOAT_64_TYPE: {
            gint length = get_native_type_cdr_length(member_kind);
            if (show) {
                ALIGN_ZERO(offset, get_native_type_cdr_alignment(member_kind, encoding_version), offset_zero);
                gdouble value = tvb_get_ieee_double(tvb, offset, encoding);
                proto_tree_add_double_format(tree, hf_rtps_dissection_double, tvb, offset, length, value,
                  "%s: %.6f", name, value);
            }
            offset += length;
            break;
        }
        case RTI_CDR_TYPE_OBJECT_TYPE_KIND_FLOAT_128_TYPE: {
            gint length = get_native_type_cdr_length(member_kind);
            if (show) {
                ALIGN_ZERO(offset, get_native_type_cdr_alignment(member_kind, encoding_version), offset_zero);
                proto_tree_add_item(tree, hf_rtps_dissection_int128, tvb, offset, length, encoding);
            }
            offset += length;
            break;
        }
        case RTI_CDR_TYPE_OBJECT_TYPE_KIND_ARRAY_TYPE: {
            guint i;
            guint num_elements;
            proto_tree * aux_tree = NULL;
            gint base_offset = offset;
            gboolean show_current_element = TRUE;
            gint array_kind_length = 0;
            guint bound = (guint)info->bound;
            gint first_skipped_element_offset = 0;

            /* In case this array is not shown and is a native type. We get the sze length for calculating
             * the whole array length */
            array_kind_length = get_native_type_cdr_length(info->base_type_id);

            /* Do not add any information to the tree if it is not shown */
            if (show) {
                aux_tree = proto_tree_add_subtree(tree, tvb, offset, -1, ett_rtps_dissection_tree,
                    NULL, name);
            } else if (array_kind_length != -1) {
                /* Total length of the array. Nothing elese to do here. */
                offset += bound * array_kind_length;
                break;
            }

            /* Get the maximun number of elements to be shown */
            num_elements = (enable_max_array_data_type_elements)
                ? MIN(bound, rtps_max_array_data_type_elements)
                : bound;
            for (i = 0; i < bound; i++) {
                gchar temp_buff[MAX_MEMBER_NAME];

                if (show && i < num_elements) {
                    /* No need to copy if it will not be shown */
                    snprintf(temp_buff, MAX_MEMBER_NAME, "%s[%u]", name, i);
                    show_current_element = TRUE;
                } else {
                    if (show_current_element) {
                        show_current_element = FALSE;
                        /* Updated only once */
                        first_skipped_element_offset = offset;
                    }
                    /* If this array has elements that won't be shown and is an array of native type
                     * we can calculate the total offset and break the loop */
                    if (array_kind_length != -1) {
                        offset += (bound - i) * array_kind_length;
                        break;
                    }
                }
                offset = dissect_user_defined(aux_tree, tvb, offset, encoding, encoding_version, NULL,
                        info->base_type_id, temp_buff, EXTENSIBILITY_INVALID, offset_zero, 0, 0, show_current_element);
            }

            /* If reached the limit and there are remaining elements we need to show the message and
             * assign the length of the ramining elements to this */
            if (enable_max_array_data_type_elements && show && !show_current_element) {
                proto_tree_add_subtree_format(
                    aux_tree,
                    tvb,
                    /* Start at the first item not shown */
                    first_skipped_element_offset,
                    offset - first_skipped_element_offset,
                    ett_rtps_info_remaining_items,
                    NULL,
                    DISSECTION_INFO_REMAINING_ELEMENTS_STR_d,
                    bound - num_elements);
            }
            proto_item_set_len(aux_tree, offset - base_offset);
            break;
        }
        case RTI_CDR_TYPE_OBJECT_TYPE_KIND_SEQUENCE_TYPE: {
            guint i;
            guint num_elements;
            proto_tree * aux_tree = NULL;
            gint base_offset = offset;
            gboolean show_current_element = TRUE;
            gint length = 4;
            gint sequence_kind_length = 0;
            gint first_skipped_element_offset = 0;

            ALIGN_ZERO(offset, length, offset_zero);
            guint seq_size =  tvb_get_guint32(tvb, offset, encoding);

            /* In case this sequence is not shown and is a native type. We get the sze length for calculating
             * the whole seuqnece length */
            sequence_kind_length = get_native_type_cdr_length(info->base_type_id);
            if (show) {
                aux_tree = proto_tree_add_subtree_format(tree, tvb, offset, -1, ett_rtps_dissection_tree,
                    NULL, "%s (%u elements)", name, seq_size);
            /* If it is a native type we can calculate the sequence length and finish. */
            } else if (sequence_kind_length != -1) {
                /* Number of elements integer size + number of elements * size of the native type */
                offset += 4 + seq_size * sequence_kind_length;
                break;
            }
            offset += 4;

            num_elements = (enable_max_array_data_type_elements)
                ? MIN(seq_size, rtps_max_array_data_type_elements)
                : seq_size;
            for (i = 0; i < seq_size; i++) {
                gchar temp_buff[MAX_MEMBER_NAME];
                if (show && i < num_elements) {
                    /* No need to copy if it will not be shown */
                    snprintf(temp_buff, MAX_MEMBER_NAME, "%s[%u]", name, i);
                    show_current_element = TRUE;
                } else {
                    if (show_current_element) {
                        show_current_element = FALSE;
                        /* Updated only once */
                        first_skipped_element_offset = offset;
                    }
                    /* If this array has elements that won't be shown and is an array of native type
                     * we can calculate the total offset and break the loop */
                    if (sequence_kind_length != -1) {
                        offset += (seq_size - i) * sequence_kind_length;
                        break;
                    }
                }
                if (info->base_type_id > 0)
                    offset = dissect_user_defined(aux_tree, tvb, offset, encoding, encoding_version, NULL,
                         info->base_type_id, temp_buff, EXTENSIBILITY_INVALID, offset_zero, 0, 0, show_current_element);
            }
            /* If reached the limit and there are remaining elements we need to show the message and
             * assign the length of the ramining elements to this */
            if (enable_max_array_data_type_elements && show && !show_current_element) {
                proto_tree_add_subtree_format(
                    aux_tree,
                    tvb,
                    /* Start at the first item not shown */
                    first_skipped_element_offset,
                    offset - first_skipped_element_offset,
                    ett_rtps_info_remaining_items,
                    NULL,
                    DISSECTION_INFO_REMAINING_ELEMENTS_STR_d,
                    seq_size - num_elements);
            }
            proto_item_set_len(aux_tree, offset - base_offset);
            break;
        }
        case RTI_CDR_TYPE_OBJECT_TYPE_KIND_STRING_TYPE: {
            gchar * string_value = NULL;
            gint length = 4;

            ALIGN_ZERO(offset, length, offset_zero);
            guint string_size =  tvb_get_guint32(tvb, offset, encoding);
            offset += 4;
            //proto_item_append_text(tree, "(String length: %u)", string_size);
            if (show) {
                string_value = tvb_get_string_enc(wmem_packet_scope(), tvb, offset, string_size, ENC_ASCII);
                proto_tree_add_string_format(tree, hf_rtps_dissection_string, tvb, offset, string_size,
                  string_value, "%s: %s", name, string_value);
            }
            offset += string_size;
            break;
        }
        case RTI_CDR_TYPE_OBJECT_TYPE_KIND_ALIAS_TYPE: {
            offset = dissect_user_defined(tree, tvb, offset, encoding, encoding_version, NULL,
                         info->base_type_id, name, EXTENSIBILITY_INVALID, offset_zero, 0, 0, show);
            break;
        }
        case RTI_CDR_TYPE_OBJECT_TYPE_KIND_UNION_TYPE: {
            guint64 key = type_id - 1;
            union_member_mapping * result = (union_member_mapping *)wmem_map_lookup(union_member_mappings, &(key));

            if (result != NULL) {
                gint value =  tvb_get_gint32(tvb, offset, encoding);
                offset += 4;
                key = type_id + value;
                result = (union_member_mapping *)wmem_map_lookup(union_member_mappings, &(key));
                if (result != NULL) {
                    if (show) {
                        proto_item_append_text(tree, " (discriminator = %d, type_id = 0x%016" PRIx64 ")",
                            value, result->member_type_id);
                    }
                  offset = dissect_user_defined(tree, tvb, offset, encoding, encoding_version, NULL,
                      result->member_type_id, result->member_name, EXTENSIBILITY_INVALID, offset, 0, 0, show);
                } else {
                    /* the hashmap uses the type_id to index the objects. substracting -2 here to lookup the discriminator
                        related to the type_id that identifies an union */
                    key = type_id + HASHMAP_DISCRIMINATOR_CONSTANT;
                    result = (union_member_mapping *)wmem_map_lookup(union_member_mappings, &(key));
                    if (result != NULL) {
                        if (show) {
                            proto_item_append_text(tree, " (discriminator = %d, type_id = 0x%016" PRIx64 ")",
                                value, result->member_type_id);
                        }
                    offset = dissect_user_defined(tree, tvb, offset, encoding, encoding_version, NULL,
                        result->member_type_id, result->member_name, EXTENSIBILITY_INVALID, offset, 0, 0, show);
                    }
                }
            } else {
                if (show) {
                  proto_item_append_text(tree, "(NULL 0x%016" PRIx64 ")", type_id);
                }
            }
            break;
        }
        case RTI_CDR_TYPE_OBJECT_TYPE_KIND_STRUCTURE_TYPE: {
            guint i;
            proto_tree * aux_tree = NULL;
            guint shown_elements = 0;
            gboolean show_current_element = TRUE;
            guint num_elements = 0;
            gint first_skipped_element_offset = 0;

            if (show) {
                aux_tree = proto_tree_add_subtree(tree, tvb, offset, -1, ett_rtps_dissection_tree,
                    NULL, name);
            }
            if (info->extensibility == EXTENSIBILITY_MUTABLE) {
                gboolean is_end = FALSE;
                /* Don't know beforehand the number of elements. Need to count them */
                while (!is_end) {
                    if (!(show && shown_elements < rtps_max_data_type_elements) && show_current_element) {
                        show_current_element = FALSE;
                        /* Updated only once */
                        first_skipped_element_offset = offset;
                        }
                    offset = dissect_mutable_member(aux_tree, tvb, offset, encoding, encoding_version, info, &is_end, show_current_element);
                    ++num_elements;
                    if (show_current_element) {
                        ++shown_elements;
                    }
                }
            } else {
                if (info->base_type_id > 0) {
                    if (show) {
                      proto_item_append_text(tree, "(BaseId: 0x%016" PRIx64 ")", info->base_type_id);
                    }
                    offset = dissect_user_defined(aux_tree, tvb, offset, encoding, encoding_version, NULL,
                            info->base_type_id, info->member_name, EXTENSIBILITY_INVALID,
                            offset, 0, 0, show);
                }

                /* Get the maximun number of elements to be shown depending if enable_max_data_type_elements is enabled */
                shown_elements = (enable_max_data_type_elements)
                        ? MIN(info->num_elements, rtps_max_data_type_elements)
                        : info->num_elements;
                for (i = 0; i < info->num_elements; i++) {
                    if (info->elements[i].type_id > 0) {
                        /* A member is shown if the parent cluster is shown and the position is in the
                        * range of maximun number of elements shown */
                        if (!(show && i < shown_elements) && show_current_element) {
                            show_current_element = FALSE;
                            /* Updated only once */
                            first_skipped_element_offset = offset;
                        }
                        /* If a member is not shown all it children will inherit the "show_current_element" value */
                        offset = dissect_user_defined(aux_tree, tvb, offset, encoding, encoding_version, NULL,
                        info->elements[i].type_id, info->elements[i].member_name, info->extensibility,
                        offset_zero, info->elements[i].flags, info->elements[i].member_id, show_current_element);
                    }
                }
                num_elements = info->num_elements;
            }
            /* If reached the limit and there are remaining elements we need to show the message and
             * assign the length of the ramining elements to this */
            if (enable_max_array_data_type_elements && show && !show_current_element) {
                proto_tree_add_subtree_format(
                    aux_tree,
                    tvb,
                    first_skipped_element_offset,
                    offset - first_skipped_element_offset,
                    ett_rtps_info_remaining_items,
                    NULL,
                    DISSECTION_INFO_REMAINING_ELEMENTS_STR_d,
                    num_elements - shown_elements);
            }
        break;
        }
        default:{
            /* undefined behavior. this should not happen. the following line helps to debug if it happened */
            if (show) {
                 proto_item_append_text(tree, "(unknown 0x%016" PRIx64 ")", member_kind);
            }
            break;
        }
    }

    if (extensibility == EXTENSIBILITY_MUTABLE) {
        offset_zero += member_length;
        return offset_zero;
    } else {
        return offset;
    }
}

static gint dissect_mutable_member(proto_tree *tree , tvbuff_t * tvb, gint offset, guint encoding, guint encoding_version,
        dissection_info * info, gboolean * is_end, gboolean show) {

    proto_tree * member;
    guint32 member_id, member_length;
    mutable_member_mapping * mapping;
    gint64 key;

    rtps_util_dissect_parameter_header(tvb, &offset, encoding, &member_id, &member_length);
    if ((member_id & PID_LIST_END) == PID_LIST_END){
    /* If this is the end of the list, don't add a tree.
    * If we add more logic here in the future, take into account that
    * offset is incremented by 4 */
        offset += 0;
        *is_end = TRUE;
        return offset;
    }
    if (member_length == 0){
        return offset;
    }
    member = proto_tree_add_subtree_format(tree, tvb, offset, member_length, ett_rtps_dissection_tree,
        NULL, "ID: %d, Length: %d", member_id, member_length);

    {
        if (info->base_type_id > 0) {
            key = (info->base_type_id + info->base_type_id * member_id);
            mapping = (mutable_member_mapping *) wmem_map_lookup(mutable_member_mappings, &(key));
            if (mapping) { /* the library knows how to dissect this */
                proto_item_append_text(member, "(base found 0x%016" PRIx64 ")", key);
                dissect_user_defined(tree, tvb, offset, encoding, encoding_version, NULL, mapping->member_type_id,
                    mapping->member_name, EXTENSIBILITY_INVALID, offset, 0, mapping->member_id, show);
                PROTO_ITEM_SET_HIDDEN(member);
                return offset + member_length;
            } else
                proto_item_append_text(member, "(base not found 0x%016" PRIx64 " from 0x%016" PRIx64 ")",
                  key, info->base_type_id);
        }
    }

    key = (info->type_id + info->type_id * member_id);
    mapping = (mutable_member_mapping *) wmem_map_lookup(mutable_member_mappings, &(key));
    if (mapping) { /* the library knows how to dissect this */
        proto_item_append_text(member, "(found 0x%016" PRIx64 ")", key);
        dissect_user_defined(tree, tvb, offset, encoding, encoding_version, NULL, mapping->member_type_id,
            mapping->member_name, EXTENSIBILITY_INVALID, offset, 0, mapping->member_id, show);

    } else
        proto_item_append_text(member, "(not found 0x%016" PRIx64 " from 0x%016" PRIx64 ")",
                  key, info->type_id);
    PROTO_ITEM_SET_HIDDEN(member);
    return offset + member_length;
}


/* *********************************************************************** */
/* Appends extra formatting for those submessages that have a status info
 */
static void append_status_info(packet_info *pinfo,
                        guint32 writer_id,
                        guint32 status_info) {

  /* Defines the extra information associated to the writer involved in
   * this communication
   *
   * Format: [?Ptwrpm]\(u?d?\)
   *
   * First letter table:
   *
   *    writerEntityId value                                   | Letter
   * ----------------------------------------------------------+--------
   * ENTITYID_UNKNOWN                                          | ?
   * ENTITYID_PARTICIPANT                                      | P
   * ENTITYID_SEDP_BUILTIN_TOPIC_WRITER                        | t
   * ENTITYID_SEDP_BUILTIN_PUBLICATIONS_WRITER                 | w
   * ENTITYID_SEDP_BUILTIN_SUBSCRIPTIONS_WRITER                | r
   * ENTITYID_SPDP_BUILTIN_PARTICIPANT_WRITER                  | p
   * ENTITYID_P2P_BUILTIN_PARTICIPANT_MESSAGE_WRITER           | m
   * ENTITYID_P2P_BUILTIN_PARTICIPANT_STATELESS_WRITER         | s
   * ENTITYID_P2P_BUILTIN_PARTICIPANT_VOLATILE_SECURE_WRITER   | V
   * ENTITYID_P2P_BUILTIN_PARTICIPANT_MESSAGE_SECURE_WRITER    | M
   * ENTITYID_SEDP_BUILTIN_PUBLICATIONS_SECURE_WRITER          | W
   * ENTITYID_SEDP_BUILTIN_SUBSCRIPTIONS_SECURE_WRITER         | R

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
  gchar * writerId = NULL;
  gchar * disposeFlag = NULL;
  gchar * unregisterFlag = NULL;
  wmem_strbuf_t *buffer = wmem_strbuf_new_label(wmem_packet_scope());

  switch(writer_id) {
    case ENTITYID_PARTICIPANT:
    case ENTITYID_SPDP_RELIABLE_BUILTIN_PARTICIPANT_SECURE_WRITER:
      writerId = "P";
      break;
    case ENTITYID_BUILTIN_TOPIC_WRITER:
      writerId = "t";
      break;
    case ENTITYID_BUILTIN_PUBLICATIONS_WRITER:
      writerId = "w";
      break;
    case ENTITYID_BUILTIN_SUBSCRIPTIONS_WRITER:
      writerId = "r";
      break;
    case ENTITYID_BUILTIN_PARTICIPANT_WRITER:
      writerId = "p";
      break;
    case ENTITYID_P2P_BUILTIN_PARTICIPANT_MESSAGE_WRITER:
      writerId = "m";
      break;
    case ENTITYID_P2P_BUILTIN_PARTICIPANT_STATELESS_WRITER:
      writerId = "s";
      break;
    case ENTITYID_P2P_BUILTIN_PARTICIPANT_VOLATILE_SECURE_WRITER:
      writerId = "V";
      break;
    case ENTITYID_P2P_BUILTIN_PARTICIPANT_MESSAGE_SECURE_WRITER:
      writerId = "M";
      break;
    case ENTITYID_SEDP_BUILTIN_PUBLICATIONS_SECURE_WRITER:
      writerId = "W";
      break;
    case ENTITYID_SEDP_BUILTIN_SUBSCRIPTIONS_SECURE_WRITER:
      writerId = "R";
      break;
    default:
    /* Unknown writer ID, don't format anything */
      break;
  }

  switch(status_info) {
    case 0: unregisterFlag = "_"; disposeFlag = "_"; break;
    case 1: unregisterFlag = "_"; disposeFlag = "D"; break;
    case 2: unregisterFlag = "U"; disposeFlag = "_"; break;
    case 3: unregisterFlag = "U"; disposeFlag = "D"; break;
    default:  /* Unknown status info, omit it */
      break;
  }

  if (writerId != NULL || unregisterFlag != NULL ||
          disposeFlag != NULL ) {
    wmem_strbuf_append(buffer, "(");
    if (writerId != NULL) {
        wmem_strbuf_append(buffer, writerId);
    }
    if (unregisterFlag != NULL || disposeFlag != NULL) {
      wmem_strbuf_append(buffer, "[");
      wmem_strbuf_append(buffer, unregisterFlag);
      wmem_strbuf_append(buffer, disposeFlag);
      wmem_strbuf_append(buffer, "]");
    }
    wmem_strbuf_append(buffer, ")");
    col_append_str(pinfo->cinfo, COL_INFO, wmem_strbuf_get_str(buffer));
   }
}

/* *********************************************************************** */

/*
 * Coherent set starts if seqNumber == writerSeqNumber
 *
 * Coherent sets end in three different ways:
 * - A new coherence set starts with the consecutive writerSeqNumber of the last coherent set packet.
 *   -seqNumber == RTPS_SEQUENCENUMBER_UNKNOWN
 * - A DATA packet sent with the consecutive writerSeqNumber of the last coherent set packet.
 * - PID_END_COHERENT_SET received. That condition is not handled here. Check PID_END_COHERENT_SET dissection.
 * Empty Data condition is not handled here. rtps_util_detect_coherent_set_end_empty_data_case called at the end of dissect_RTPS_DATA and dissect_RTPS_DATA_FRAG_kind
 */
static void rtps_util_add_coherent_set_general_cases_case(
  proto_tree *tree,
  tvbuff_t *tvb,
  guint64 coherent_seq_number,
  coherent_set_entity_info *coherent_set_entity_info_object) {

  coherent_set_entity_info *register_entry;
  proto_tree *marked_item_tree;
  coherent_set_info *coherent_set_info_entry;
  coherent_set_key coherent_set_info_key;

  coherent_set_entity_info_object->coherent_set_seq_number = coherent_seq_number;
  register_entry = (coherent_set_entity_info*)wmem_map_lookup(coherent_set_tracking.entities_using_map,
    &coherent_set_entity_info_object->guid);
  if (!register_entry) {
    register_entry = (coherent_set_entity_info*)wmem_memdup(wmem_file_scope(), coherent_set_entity_info_object, sizeof(coherent_set_entity_info));
    wmem_map_insert(
      coherent_set_tracking.entities_using_map,
      &register_entry->guid,
      register_entry);
  }

  /* The hash and compare functions treat the key as a sequence of bytes */
  memset(&coherent_set_info_key, 0, sizeof(coherent_set_info_key));
  coherent_set_info_key.guid = coherent_set_entity_info_object->guid;
  coherent_set_info_key.coherent_set_seq_number = coherent_seq_number;
  coherent_set_info_entry = (coherent_set_info*)wmem_map_lookup(coherent_set_tracking.coherent_set_registry_map,
    &coherent_set_info_key);
  if (!coherent_set_info_entry) {
    coherent_set_info_entry = wmem_new0(wmem_file_scope(), coherent_set_info);
    coherent_set_info_entry->key = (coherent_set_key*)wmem_memdup(wmem_file_scope(), &coherent_set_info_key, sizeof(coherent_set_key));
    coherent_set_info_entry->is_set = FALSE;
    wmem_map_insert(
      coherent_set_tracking.coherent_set_registry_map,
      coherent_set_info_entry->key,
      coherent_set_info_entry);
  }

  if (coherent_set_info_entry->writer_seq_number < coherent_set_entity_info_object->writer_seq_number) {
    coherent_set_info_entry->writer_seq_number = coherent_set_entity_info_object->writer_seq_number;
  }
  /* Start */
  if (coherent_set_entity_info_object->coherent_set_seq_number == coherent_set_entity_info_object->writer_seq_number) {
    marked_item_tree = proto_tree_add_uint64(tree, hf_rtps_coherent_set_start,
      tvb, 0, 0, coherent_seq_number);
    proto_item_set_generated(marked_item_tree);

    /* End case: Start of a new coherent set */
    if (coherent_set_entity_info_object->coherent_set_seq_number > register_entry->coherent_set_seq_number &&
      coherent_set_entity_info_object->writer_seq_number - 1 == register_entry->writer_seq_number) {
      coherent_set_info *previous_entry;

      marked_item_tree = proto_tree_add_uint64(tree, hf_rtps_coherent_set_end,
        tvb, 0, 0, register_entry->coherent_set_seq_number);
      proto_item_set_generated(marked_item_tree);
      coherent_set_info_key.coherent_set_seq_number = register_entry->writer_seq_number;
      coherent_set_info_key.guid = register_entry->guid;
      previous_entry = (coherent_set_info*)wmem_map_lookup(coherent_set_tracking.coherent_set_registry_map, &coherent_set_info_key);
      if (previous_entry) {
        previous_entry->is_set = TRUE;
      }
    }
  }

  if (!coherent_set_info_entry->is_set) {

    coherent_set_info_key.coherent_set_seq_number = coherent_seq_number - 1;

    /* End case: Sequence unknown received */

    if (coherent_set_entity_info_object->coherent_set_seq_number == RTPS_SEQUENCENUMBER_UNKNOWN) {
      register_entry->coherent_set_seq_number = coherent_set_entity_info_object->coherent_set_seq_number;
      marked_item_tree = proto_tree_add_uint64(tree, hf_rtps_coherent_set_end,
        tvb, 0, 0, coherent_set_info_entry->key->coherent_set_seq_number);
      proto_item_set_generated(marked_item_tree);
      coherent_set_info_entry->is_set = TRUE;
    }
  } else if (coherent_set_info_entry->writer_seq_number == coherent_set_entity_info_object->writer_seq_number) {
    proto_tree *ti;

    ti = proto_tree_add_uint64(tree, hf_rtps_coherent_set_end,
      tvb, 0, 0, coherent_set_info_entry->key->coherent_set_seq_number);
    proto_item_set_generated(ti);
  }
  /* Update the entity */
  coherent_set_entity_info_object->expected_coherent_set_end_writers_seq_number = coherent_set_entity_info_object->writer_seq_number + 1;
  *register_entry = *coherent_set_entity_info_object;
}

/*
 * Handles the coherent set termination case where the coherent set finishes by sending a DATA or DATA_FRAG with no parameters.
 * For the other cases, check rtps_util_add_coherent_set_general_cases_case.
 * this function must be called at the end of dissect_RTPS_DATA and dissect_RTPS_DATA_FRAG_kind
 */
static void rtps_util_detect_coherent_set_end_empty_data_case(

  coherent_set_entity_info *coherent_set_entity_info_object) {
  coherent_set_entity_info *coherent_set_entry = NULL;

  coherent_set_entry = (coherent_set_entity_info*) wmem_map_lookup(coherent_set_tracking.entities_using_map, &coherent_set_entity_info_object->guid);
  if (coherent_set_entry) {
    coherent_set_info *coherent_set_info_entry;
    coherent_set_key key;

    /* The hash and compare functions treat the key as a sequence of bytes. */
    memset(&key, 0, sizeof(key));
    key.guid = coherent_set_entity_info_object->guid;
    key.coherent_set_seq_number = coherent_set_entry->coherent_set_seq_number;

    coherent_set_info_entry = (coherent_set_info*)wmem_map_lookup(coherent_set_tracking.coherent_set_registry_map, &key);
    if (coherent_set_info_entry
                && coherent_set_entry->expected_coherent_set_end_writers_seq_number == coherent_set_entity_info_object->writer_seq_number
                && !coherent_set_info_entry->is_set) {
        coherent_set_info_entry->is_set = TRUE;
        coherent_set_info_entry->writer_seq_number = coherent_set_entry->expected_coherent_set_end_writers_seq_number - 1;
    }
  }
}

static guint16 rtps_util_add_protocol_version(proto_tree *tree, /* Can NOT be NULL */
                        tvbuff_t *tvb,
                        gint      offset) {
  proto_item *ti;
  proto_tree *version_tree;
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
static guint16 rtps_util_add_vendor_id(proto_tree *tree,
                        tvbuff_t *tvb,
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
static gint rtps_util_add_locator_t(proto_tree *tree, packet_info *pinfo, tvbuff_t *tvb, gint offset,
                             const guint encoding, const char *label) {

  proto_tree *ti;
  proto_tree *locator_tree;
  guint32 kind;
  guint32 port;
  const gint parameter_size = 24;

  locator_tree = proto_tree_add_subtree(tree, tvb, offset, parameter_size, ett_rtps_locator,
          NULL, label);

  proto_tree_add_item_ret_uint(locator_tree, hf_rtps_locator_kind, tvb, offset, 4, encoding, &kind);
  switch (kind) {
    case LOCATOR_KIND_UDPV4:
    case LOCATOR_KIND_TUDPV4: {
      ti = proto_tree_add_item_ret_uint(
              locator_tree,
              hf_rtps_locator_port,
              tvb,
              offset + 4,
              4,
              encoding,
              &port);

      if (port == 0)
        expert_add_info(pinfo, ti, &ei_rtps_locator_port);
      proto_item_append_text(tree, " (%s, %s:%u)",
                 val_to_str(kind, rtps_locator_kind_vals, "%02x"),
                 tvb_ip_to_str(pinfo->pool, tvb, offset + 20), port);
      break;
    }
    case LOCATOR_KIND_TCPV4_LAN:
    case LOCATOR_KIND_TCPV4_WAN:
    case LOCATOR_KIND_TLSV4_LAN:
    case LOCATOR_KIND_TLSV4_WAN: {
      guint16 ip_kind;
      ti = proto_tree_add_item_ret_uint(
              locator_tree,
              hf_rtps_locator_port,
              tvb,
              offset + 4,
              4,
              encoding,
              &port);
      if (port == 0)
        expert_add_info(pinfo, ti, &ei_rtps_locator_port);
      ip_kind = tvb_get_guint16(tvb, offset+16, encoding);
      if (ip_kind == 0xFFFF) { /* IPv4 format */
        guint16 public_address_port = tvb_get_guint16(tvb, offset + 18, ENC_BIG_ENDIAN);
        proto_tree_add_item(locator_tree, hf_rtps_locator_public_address_port,
                tvb, offset+18, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item(locator_tree, hf_rtps_locator_ipv4, tvb, offset+20,
                4, ENC_BIG_ENDIAN);
        proto_item_append_text(tree, " (%s, %s:%d, Logical Port = %u)",
                   val_to_str(kind, rtps_locator_kind_vals, "%02x"),
                   tvb_ip_to_str(pinfo->pool, tvb, offset + 20), public_address_port, port);
        } else { /* IPv6 format */
          proto_tree_add_item(locator_tree, hf_rtps_locator_ipv6, tvb, offset+8,
                  16, ENC_NA);
          proto_item_append_text(tree, " (%s, %s, Logical Port = %u)",
                  val_to_str(kind, rtps_locator_kind_vals, "%02x"),
                  tvb_ip6_to_str(pinfo->pool, tvb, offset + 8), port);
        }
      break;
    }
    case LOCATOR_KIND_SHMEM: {
      guint32 hostId;
      ti = proto_tree_add_item_ret_uint(
              locator_tree,
              hf_rtps_locator_port,
              tvb,
              offset + 4,
              4,
              encoding,
              &port);
      proto_tree_add_item_ret_uint(locator_tree, hf_rtps_param_host_id, tvb, offset+10, 4, ENC_BIG_ENDIAN, &hostId);
      if (port == 0)
        expert_add_info(pinfo, ti, &ei_rtps_locator_port);
      proto_item_append_text(tree, " (%s, HostId = 0x%08x, Port = %u)",
              val_to_str(kind, rtps_locator_kind_vals, "%02x"),
              hostId, port);
      break;
    }
    case LOCATOR_KIND_UDPV6: {
      ti = proto_tree_add_item_ret_uint(
              locator_tree,
              hf_rtps_locator_port,
              tvb,
              offset + 4,
              4,
              encoding,
              &port);
      if (port == 0)
        expert_add_info(pinfo, ti, &ei_rtps_locator_port);
      proto_tree_add_item(locator_tree, hf_rtps_locator_ipv6, tvb, offset+8, 16, ENC_NA);
      proto_item_append_text(tree, " (%s, %s:%u)",
              val_to_str(kind, rtps_locator_kind_vals, "%02x"),
              tvb_ip6_to_str(pinfo->pool, tvb, offset + 8), port);
      break;
    }
    case LOCATOR_KIND_DTLS: {
      proto_tree_add_item_ret_uint(
              locator_tree,
              hf_rtps_locator_port,
              tvb,
              offset + 4,
              4,
              encoding,
              &port);
      proto_tree_add_item(locator_tree, hf_rtps_locator_ipv6, tvb, offset+8, 16, ENC_NA);
      proto_item_append_text(tree, " (%s, %s:%u)",
              val_to_str(kind, rtps_locator_kind_vals, "%02x"),
              tvb_ip6_to_str(pinfo->pool, tvb, offset + 8), port);
      break;
    }
    /*
     * +-------+-------+-------+-------+
     * | Flags |                       |
     * +-------+                       +
     * |       DDS_Octet UUID[9]       |
     * +               +-------+-------+
     * |               | public_port   |
     * +-------+-------+-------+-------+
     * | DDS_Octet public_ip_address[4]|
     * +-------+-------+-------+-------+
     */
    case LOCATOR_KIND_UDPV4_WAN: {
        guint8 flags = 0;
        ws_in4_addr locator_ip = 0;
        const guint32 uuid_size = 9;
        const guint32 locator_port_size = 4;
        const guint32 locator_port_offset = offset + 4;
        const guint32 flags_offset = locator_port_offset + locator_port_size;
        const guint32 uuid_offset = flags_offset + 1;
        const guint32 port_offset = uuid_offset + uuid_size;
        const guint32 ip_offset = port_offset + 2;
        int hf_port = 0;
        int hf_ip = 0;
        gchar* ip_str = NULL;
        guint32 public_port = 0;
        gboolean is_public = FALSE;

        ti = proto_tree_add_item_ret_uint(
                locator_tree,
                hf_rtps_locator_port,
                tvb,
                locator_port_offset,
                locator_port_size,
                encoding,
                &port);
        flags = tvb_get_gint8(tvb, flags_offset);
        proto_tree_add_bitmask_value(
                locator_tree,
                tvb,
                flags_offset,
                hf_rtps_udpv4_wan_locator_flags,
                ett_rtps_flags,
                UDPV4_WAN_LOCATOR_FLAGS,
                (guint64)flags);

        /* UUID */
        proto_tree_add_item(locator_tree, hf_rtps_uuid, tvb, uuid_offset, UUID_SIZE, encoding);

        /*
         * The P flag indicates that the locator contains a globally public IP address
         * and public port where a transport instance can be reached. public_ip_address
         * contains the public IP address and public_port contains the public UDP port.
         * Locators with the P flag set are called PUBLIC locators.
         */
        is_public = ((flags & FLAG_UDPV4_WAN_LOCATOR_P) != 0);
        if (is_public) {
            hf_ip = hf_rtps_udpv4_wan_locator_public_ip;
            hf_port = hf_rtps_udpv4_wan_locator_public_port;
        } else {
            hf_ip = hf_rtps_udpv4_wan_locator_local_ip;
            hf_port = hf_rtps_udpv4_wan_locator_local_port;
        }

        /* Port & IP */
        ip_str = tvb_ip_to_str(pinfo->pool, tvb, ip_offset);
        locator_ip = tvb_get_ipv4(tvb, ip_offset);
        if (locator_ip != 0) {
            proto_tree_add_item_ret_uint(
                locator_tree,
                hf_port,
                tvb,
                port_offset,
                2,
                ENC_NA,
                &public_port);
            proto_tree_add_ipv4(
                locator_tree,
                hf_ip,
                tvb,
                ip_offset,
                4,
                locator_ip);
        }
        if (port == 0)
            expert_add_info(pinfo, ti, &ei_rtps_locator_port);
        if (ip_str != NULL && locator_ip != 0) {
            if (is_public) {
                proto_item_append_text(tree, " (%s, public: %s:%u, rtps port:%u)",
                    val_to_str(kind, rtps_locator_kind_vals, "%02x"),
                    ip_str, public_port, port);
            } else {
                proto_item_append_text(tree, " (%s, local: %s:%u)",
                    val_to_str(kind, rtps_locator_kind_vals, "%02x"),
                    ip_str, port);
            }
        }
    }
    /* Default case, we already have the locator kind so don't do anything */
    default:
      break;
  }
  return offset + parameter_size;
}

/* ------------------------------------------------------------------------- */
/* Insert in the protocol tree the next bytes interpreted as Sequence of
 * unsigned shorts.
 * The formatted buffer is: val1, val2, val3, ...
 * Returns the new updated offset
 */
static gint rtps_util_add_seq_short(proto_tree *tree, tvbuff_t *tvb, gint offset, int hf_item,
  const guint encoding, int param_length _U_, const char *label) {
  guint32 num_elem;
  guint32 i;
  proto_tree *string_tree;

  num_elem = tvb_get_guint32(tvb, offset, encoding);
  offset += 4;

  /* Create the string node with an empty string, the replace it later */
  string_tree = proto_tree_add_subtree_format(tree, tvb, offset, num_elem * 4,
    ett_rtps_seq_ulong, NULL, "%s (%d elements)", label, num_elem);

  for (i = 0; i < num_elem; ++i) {
    proto_tree_add_item(string_tree, hf_item, tvb, offset, 2, encoding);
    offset += 2;
  }

  return offset;
}

static gint rtps_util_add_locator_ex_t(proto_tree *tree, packet_info *pinfo, tvbuff_t *tvb, gint offset,
  const guint encoding, int param_length) {
  gint locator_offset = 0;

  locator_offset = rtps_util_add_locator_t(tree, pinfo, tvb,
    offset, encoding, "locator");
  offset += rtps_util_add_seq_short(tree, tvb, locator_offset, hf_rtps_encapsulation_id,
    encoding, param_length - (locator_offset - offset), "encapsulations");
  return offset;
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
static int rtps_util_add_locator_list(proto_tree *tree, packet_info *pinfo, tvbuff_t *tvb,
                                gint offset, const guint8 *label, const guint encoding) {

  proto_tree *locator_tree;
  guint32 num_locators;

  num_locators = tvb_get_guint32(tvb, offset, encoding);

  locator_tree = proto_tree_add_subtree_format(tree, tvb, offset, 4,
                        ett_rtps_locator_udp_v4, NULL, "%s: %d Locators", label, num_locators);
  offset += 4;
  if (num_locators > 0) {
    guint32 i;
    char temp_buff[20];

    for (i = 0; i < num_locators; ++i) {
      snprintf(temp_buff, 20, "Locator[%d]", i);
      rtps_util_add_locator_t(locator_tree, pinfo, tvb, offset,
                        encoding, temp_buff);
      offset += 24;
    }
  }
  return offset;
}

/* ------------------------------------------------------------------------- */
/* Insert in the protocol tree the next bytes interpreted as a list of
* multichannel Locators:
*   - unsigned long numLocators
*   - locator 1
*   - locator 2
*   - ...
*   - locator n
* Returns the new offset after parsing the locator list
*/
static int rtps_util_add_multichannel_locator_list(proto_tree *tree, packet_info *pinfo, tvbuff_t *tvb,
    gint offset, const guint8 *label, const guint encoding) {

    proto_tree *locator_tree;
    guint32 num_locators;

    num_locators = tvb_get_guint32(tvb, offset, encoding);
    locator_tree = proto_tree_add_subtree_format(tree, tvb, offset, 4,
        ett_rtps_locator_udp_v4, NULL, "%s: %d Locators", label, num_locators);

    offset += 4;
    if (num_locators > 0) {
        guint32 i;
        for (i = 0; i < num_locators; ++i) {
            proto_tree *ti, *locator_item_tree;
            guint32 kind;
            guint32 port;
            gchar *channel_address;
            locator_item_tree = proto_tree_add_subtree(locator_tree, tvb, offset, 24, ett_rtps_locator,
                NULL, label);
            proto_tree_add_item_ret_uint(locator_item_tree, hf_rtps_locator_kind, tvb, offset, 4, encoding, &kind);
            switch (kind) {
            case LOCATOR_KIND_UDPV4:
            case LOCATOR_KIND_TUDPV4: {
                proto_tree_add_item(locator_item_tree, hf_rtps_locator_ipv4, tvb, offset + 16, 4,
                    ENC_BIG_ENDIAN);
                channel_address = tvb_ip_to_str(pinfo->pool, tvb, offset + 16);
                break;
            }
            case LOCATOR_KIND_UDPV6: {
                proto_tree_add_item(locator_tree, hf_rtps_locator_ipv6, tvb, offset + 4, 16, ENC_NA);
                channel_address = tvb_ip6_to_str(pinfo->pool, tvb, offset + 4);
                proto_item_append_text(tree, " (%s, %s)",
                    val_to_str(kind, rtps_locator_kind_vals, "%02x"),
                    tvb_ip6_to_str(pinfo->pool, tvb, offset + 4));
                break;
            }
                                     /* Default case, Multichannel locators only should be present in UDPv4 and UDPv6 transports
                                     * Unknown address format.
                                     * */
            default:
                offset += 24;
                continue;
                break;
            }
            ti = proto_tree_add_item_ret_uint(locator_item_tree, hf_rtps_locator_port, tvb, offset + 20, 4, encoding, &port);
            if (port == 0)
                expert_add_info(pinfo, ti, &ei_rtps_locator_port);
            proto_item_append_text(tree, " (%s, %s:%u)",
                val_to_str(kind, rtps_locator_kind_vals, "%02x"),
                channel_address, port);
            offset += 24;
        }
    }
    return offset;
}

/* ------------------------------------------------------------------------- */
/* Insert in the protocol tree the next 4 bytes interpreted as IPV4Address_t
 */
static void rtps_util_add_ipv4_address_t(proto_tree *tree, packet_info *pinfo, tvbuff_t *tvb, gint offset,
                                  const guint encoding, int hf_item) {

  proto_item *ti;

  ti = proto_tree_add_item(tree, hf_item, tvb, offset, 4, encoding);
  if (tvb_get_ntohl(tvb, offset) == IPADDRESS_INVALID)
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
static void rtps_util_add_locator_udp_v4(proto_tree *tree, packet_info *pinfo, tvbuff_t *tvb,
                                  gint offset, const guint8 *label, const guint encoding) {

  proto_item *ti;
  proto_tree *locator_tree;
  guint32 port;

  locator_tree = proto_tree_add_subtree(tree, tvb, offset, 8, ett_rtps_locator_udp_v4, NULL, label);

  rtps_util_add_ipv4_address_t(locator_tree, pinfo, tvb, offset,
                               encoding, hf_rtps_locator_udp_v4);

  ti = proto_tree_add_item_ret_uint(locator_tree, hf_rtps_locator_udp_v4_port, tvb, offset, 4, encoding, &port);
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
                        int hf_app_id_app_kind, const guint8 *label) {
  guint64 prefix;
  guint32  host_id, app_id, instance_id;
  guint8   app_kind;
  proto_item *ti;
  proto_tree *guid_tree, *appid_tree;
  const guint8 *safe_label = (label == NULL) ? (const guint8 *)"guidPrefix" : label;

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
                                      int hf_instance_id, int hf_prefix_extra) {
  if (tree) {
    proto_item *ti;
    proto_tree *guid_tree;

    /* The text node (root of the guid prefix sub-tree) */
    ti = proto_tree_add_item(tree, hf_prefix, tvb, offset, 12, ENC_NA);
    guid_tree = proto_item_add_subtree(ti, ett_rtps_guid_prefix);

    /* Optional filter that can be guidPrefix.src or guidPrefix.dst */
    if (hf_prefix_extra != 0) {
      ti = proto_tree_add_item(tree, hf_prefix_extra, tvb, offset, 12, ENC_NA);
      proto_item_set_hidden(ti);
    }

    /* Host Id */
    proto_tree_add_item(guid_tree, hf_host_id, tvb, offset, 4, ENC_BIG_ENDIAN);

    /* App Id */
    proto_tree_add_item(guid_tree, hf_app_id, tvb, offset+4, 4, ENC_BIG_ENDIAN);

    /* Counter */
    proto_tree_add_item(guid_tree, hf_instance_id, tvb, offset+8, 4, ENC_BIG_ENDIAN);
  }
}
/* ------------------------------------------------------------------------- */
 /* Insert the entityId from the next 4 bytes. Since there are more than
  * one entityId, we need to specify also the IDs of the entityId (and its
  * sub-components), as well as the label identifying it.
  * Returns true if the entityKind is one of the NDDS built-in entities.
  */
static gboolean rtps_util_add_entity_id(proto_tree *tree, tvbuff_t *tvb, gint offset,
                            int hf_item, int hf_item_entity_key, int hf_item_entity_kind,
                            int subtree_entity_id, const char *label, guint32 *entity_id_out) {
  guint32 entity_id   = tvb_get_ntohl(tvb, offset);
  guint32 entity_key  = (entity_id >> 8);
  guint8  entity_kind = (entity_id & 0xff);
  const char *str_predef = try_val_to_str(entity_id, entity_id_vals);

  if (entity_id_out != NULL) {
    *entity_id_out = entity_id;
  }

  if (tree != NULL) {
    proto_tree *entity_tree;
    proto_item *ti;

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
  return ( ((entity_kind & 0xc0) == 0xc0) ||
           entity_id == ENTITYID_RTI_BUILTIN_SERVICE_REQUEST_WRITER ||
           entity_id == ENTITYID_RTI_BUILTIN_SERVICE_REQUEST_READER ||
           entity_id == ENTITYID_RTI_BUILTIN_LOCATOR_PING_WRITER ||
           entity_id == ENTITYID_RTI_BUILTIN_LOCATOR_PING_READER);
}

/* ------------------------------------------------------------------------- */
 /* Insert the entityId from the next 4 bytes as a generic one (not connected
  * to any protocol field). It simply insert the content as a simple text entry
  * and returns in the passed buffer only the value (without the label).
  */
static void rtps_util_add_generic_entity_id(proto_tree *tree, tvbuff_t *tvb, gint offset, const char *label,
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
static void rtps_util_add_generic_guid_v1(proto_tree *tree, tvbuff_t *tvb, gint offset,
                        int hf_guid, int hf_host_id, int hf_app_id, int hf_app_id_instance_id,
                        int hf_app_id_app_kind, int hf_entity, int hf_entity_key,
                        int hf_entity_kind) {

  guint64 prefix;
  guint32 host_id, app_id, entity_id;
  proto_item *ti;
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
/* Insert in the protocol tree the next data interpreted as a String
 * Returns the new offset (after reading the string)
 */
static gint rtps_util_add_string(proto_tree *tree, tvbuff_t *tvb, gint offset,
                          int hf_item, const guint encoding) {
  guint8 *retVal = NULL;
  guint32 size = tvb_get_guint32(tvb, offset, encoding);

  retVal = tvb_get_string_enc(wmem_packet_scope(), tvb, offset+4, size, ENC_ASCII);

  proto_tree_add_string(tree, hf_item, tvb, offset, size+4, retVal);

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

static gint rtps_util_add_data_tags(proto_tree *rtps_parameter_tree, tvbuff_t *tvb,
    gint offset, const guint encoding, int param_length) {

    /* 0...2...........7...............15.............23...............31
    * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    * | Sequence Size                                                 |
    * +ITEM 0---------+---------------+---------------+---------------+
    * | Name String Bytes                                             |
    * +---------------+---------------+---------------+---------------+
    * | Value String Bytes                                            |
    * +---------------+---------------+---------------+---------------+
    * ....
    * +ITEM N---------+---------------+---------------+---------------+
    * | Name String Bytes                                             |
    * +---------------+---------------+---------------+---------------+
    * | Value String Bytes                                            |
    * +---------------+---------------+---------------+---------------+
    */

    proto_tree *tags_seq_tree = NULL;
    proto_tree *tag_tree = NULL;
    guint32 seq_sum_elements, i;

    seq_sum_elements = tvb_get_guint32(tvb, offset, encoding);
    offset += 4;

    tags_seq_tree = proto_tree_add_subtree_format(rtps_parameter_tree, tvb, offset - 4, param_length,
        ett_rtps_data_tag_seq, NULL, "Tags (size = %u)", seq_sum_elements);

    for (i = 0; i < seq_sum_elements; ++i) {
        guint32 initial_offset = offset;
        tag_tree = proto_tree_add_subtree_format(tags_seq_tree, tvb, offset, -1, ett_rtps_data_tag_item,
            NULL, "Tag [%u]", i);
        offset = rtps_util_add_string(tag_tree, tvb, offset, hf_rtps_data_tag_name, encoding);
        offset = rtps_util_add_string(tag_tree, tvb, offset, hf_rtps_data_tag_value, encoding);
        proto_item_set_len(tag_tree, offset - initial_offset);
    }
    return offset;
}



/* ------------------------------------------------------------------------- */
 /* Interpret the next 16 octets as a generic GUID and insert it in the protocol
  * tree as simple text (no reference fields are set).
  * It is mostly used in situation where is not required to perform search for
  * this kind of GUID (i.e. like in some DATA parameter lists).
  */
static void rtps_util_add_generic_guid_v2(proto_tree *tree, tvbuff_t *tvb, gint offset,
                        int hf_guid, int hf_host_id, int hf_app_id, int hf_instance_id,
                        int hf_entity, int hf_entity_key, int hf_entity_kind, proto_tree *print_tree) {

  guint32 host_id, app_id, entity_id, instance_id;
  proto_item *ti;
  proto_tree *guid_tree, *entity_tree;

  /* Read typed data */
  host_id     = tvb_get_ntohl(tvb, offset);
  app_id      = tvb_get_ntohl(tvb, offset + 4);
  instance_id = tvb_get_ntohl(tvb, offset + 8);
  entity_id   = tvb_get_ntohl(tvb, offset + 12);

  ti = proto_tree_add_bytes_format_value(tree, hf_guid, tvb, offset, 16, NULL, "%08x %08x %08x %08x",
      host_id, app_id, instance_id, entity_id);

  /* If the method is called with a valid print_tree pointer, we add the info to the tree.
   * This improves usability a lot since the user doesn't have to click a lot to debug. */
  proto_item_append_text(print_tree, "%08x %08x %08x %08x",
          host_id, app_id, instance_id, entity_id);

  guid_tree = proto_item_add_subtree(ti, ett_rtps_generic_guid);

  /* Host Id */
  proto_tree_add_item(guid_tree, hf_host_id, tvb, offset, 4, ENC_BIG_ENDIAN);

  /* App Id */
  proto_tree_add_item(guid_tree, hf_app_id, tvb, offset+4, 4, ENC_BIG_ENDIAN);

  /* Instance Id */
  proto_tree_add_item(guid_tree, hf_instance_id, tvb, offset+8, 4, ENC_BIG_ENDIAN);

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
static guint64 rtps_util_add_seq_number(proto_tree *tree,
                                 tvbuff_t   *tvb,
                                 gint        offset,
                                 const guint encoding,
                                 const char *label) {
  guint64 hi = (guint64)tvb_get_guint32(tvb, offset, encoding);
  guint64 lo = (guint64)tvb_get_guint32(tvb, offset+4, encoding);
  guint64 all = (hi << 32) | lo;

  proto_tree_add_int64_format(tree, hf_rtps_sm_seq_number, tvb, offset, 8,
                        all, "%s: %" PRIu64, label, all);

  return all;
}


/* ------------------------------------------------------------------------- */
/* Vendor specific: RTI
 * Insert in the protocol tree the next 8 bytes interpreted as TransportInfo
 */
static void rtps_util_add_transport_info(proto_tree *tree,
  tvbuff_t *tvb,
  gint      offset,
  const guint encoding,
  int       transport_index)
  {
  gint32 classId = tvb_get_guint32(tvb, offset, encoding);

  if (tree) {
    proto_tree *xport_info_tree;

    xport_info_tree = proto_tree_add_subtree_format(tree, tvb, offset, 8, ett_rtps_transport_info, NULL,
            "transportInfo %d: %s", transport_index,val_to_str(classId, ndds_transport_class_id_vals, "unknown"));

    proto_tree_add_item(xport_info_tree, hf_rtps_transportInfo_classId, tvb,
      offset, 4, encoding);
    proto_tree_add_item(xport_info_tree, hf_rtps_transportInfo_messageSizeMax, tvb,
      offset+4, 4, encoding);
  }
}

/* ------------------------------------------------------------------------- */
/* Insert in the protocol tree the next 8 bytes interpreted as an RTPS time_t,
 * which is like an NTP time stamp, except that it uses the UNIX epoch,
 * rather than the NTP epoch, as the time base.  Doesn't check for TIME_ZERO,
 * TIME_INVALID, or TIME_INFINITE, and doesn't show the seconds and
 * fraction field separately.
 */
static void rtps_util_add_timestamp(proto_tree *tree,
                        tvbuff_t *tvb,
                        gint       offset,
                        const guint encoding,
                        int hf_time) {

  proto_tree_add_item(tree, hf_time, tvb, offset, 8,
                      ENC_TIME_RTPS|encoding);

}

/* ------------------------------------------------------------------------- */
/* Insert in the protocol tree the next 8 bytes interpreted as an RTPS time_t.
 * Checks for special values except for TIME_INVALID, and shows the
 * seconds and fraction as separate fields.
 */
static void rtps_util_add_timestamp_sec_and_fraction(proto_tree *tree,
  tvbuff_t *tvb,
  gint       offset,
  const guint encoding,
  int hf_time _U_) {

  gchar  tempBuffer[MAX_TIMESTAMP_SIZE];
  gdouble absolute;
  gint32 sec;
  guint32 frac;

  if (tree) {
    proto_tree *time_tree;

    sec = tvb_get_guint32(tvb, offset, encoding);
    frac = tvb_get_guint32(tvb, offset+4, encoding);

    if ((sec == 0x7fffffff) && (frac == 0xffffffff)) {
      (void) g_strlcpy(tempBuffer, "INFINITE", MAX_TIMESTAMP_SIZE);
    } else if ((sec == 0) && (frac == 0)) {
      (void) g_strlcpy(tempBuffer, "0 sec", MAX_TIMESTAMP_SIZE);
    } else {
      absolute = (gdouble)sec + (gdouble)frac / ((gdouble)(0x80000000) * 2.0);
      snprintf(tempBuffer, MAX_TIMESTAMP_SIZE,
        "%f sec (%ds + 0x%08x)", absolute, sec, frac);
    }

    time_tree = proto_tree_add_subtree_format(tree, tvb, offset, 8,
           ett_rtps_timestamp, NULL, "%s: %s", "lease_duration", tempBuffer);

    proto_tree_add_item(time_tree, hf_rtps_param_timestamp_sec, tvb, offset, 4, encoding);
    proto_tree_add_item(time_tree, hf_rtps_param_timestamp_fraction, tvb, offset+4, 4, encoding);
  }
}

/* ------------------------------------------------------------------------- */
/* Insert in the protocol tree the next data interpreted as a port (unsigned
 * 32-bit integer)
 */
static void rtps_util_add_port(proto_tree *tree, packet_info *pinfo, tvbuff_t *tvb,
                        gint offset, const guint encoding, int hf_item) {
  proto_item *ti;
  guint32 port;

  ti = proto_tree_add_item_ret_uint(tree, hf_item, tvb, offset, 4, encoding, &port);
  if (port == PORT_INVALID)
    expert_add_info(pinfo, ti, &ei_rtps_port_invalid);
}


/* ------------------------------------------------------------------------- */
/* Insert in the protocol tree the next bytes interpreted as
 * DurabilityServiceQosPolicy
 */
static void rtps_util_add_durability_service_qos(proto_tree *tree,
                        tvbuff_t *tvb,
                        gint       offset,
                        const guint encoding) {
  proto_tree *subtree;

  subtree = proto_tree_add_subtree(tree, tvb, offset, 28, ett_rtps_durability_service, NULL, "PID_DURABILITY_SERVICE");

  rtps_util_add_timestamp_sec_and_fraction(subtree, tvb, offset, encoding, hf_rtps_durability_service_cleanup_delay);
  proto_tree_add_item(subtree, hf_rtps_durability_service_history_kind, tvb, offset+8, 4, encoding);
  proto_tree_add_item(subtree, hf_rtps_durability_service_history_depth, tvb, offset+12, 4, encoding);
  proto_tree_add_item(subtree, hf_rtps_durability_service_max_samples, tvb, offset+16, 4, encoding);
  proto_tree_add_item(subtree, hf_rtps_durability_service_max_instances, tvb, offset+20, 4, encoding);
  proto_tree_add_item(subtree, hf_rtps_durability_service_max_samples_per_instances, tvb, offset+24, 4, encoding);
}

/* ------------------------------------------------------------------------- */
/* Insert in the protocol tree the next bytes interpreted as Liveliness
 * QoS Policy structure.
 */
static void rtps_util_add_liveliness_qos(proto_tree *tree, tvbuff_t *tvb, gint offset, const guint encoding) {

  proto_tree *subtree;

  subtree = proto_tree_add_subtree(tree, tvb, offset, 12, ett_rtps_liveliness, NULL, "PID_LIVELINESS");

  proto_tree_add_item(subtree, hf_rtps_liveliness_kind, tvb, offset, 4, encoding);
  rtps_util_add_timestamp_sec_and_fraction(subtree, tvb, offset+4, encoding, hf_rtps_liveliness_lease_duration);
}

/* ------------------------------------------------------------------------- */
/* Insert in the protocol tree the next bytes interpreted as Liveliness
 * QoS Policy structure.
 */
static void rtps_util_add_product_version(proto_tree *tree, tvbuff_t *tvb, gint offset, gint vendor_id) {

  proto_tree *subtree;
  guint8 major, minor, release, revision;
  gint release_offset;
  gint revision_offset;

  release_offset = 2;
  revision_offset = 3;
  major = tvb_get_guint8(tvb, offset);
  minor = tvb_get_guint8(tvb, offset+1);
  release = tvb_get_guint8(tvb, offset+2);
  revision = tvb_get_guint8(tvb, offset+3);

  if (vendor_id == RTPS_VENDOR_RTI_DDS) {
    if (major < 5 && revision == 0) {
      subtree = proto_tree_add_subtree_format(tree, tvb, offset, 4, ett_rtps_product_version, NULL,
              "Product version: %d.%d%c", major, minor, release);
    } else if (major < 5 && revision > 0) {
          subtree = proto_tree_add_subtree_format(tree, tvb, offset, 4, ett_rtps_product_version, NULL,
              "Product version: %d.%d%c rev%d", major, minor, release, revision);
    } else {
          subtree = proto_tree_add_subtree_format(tree, tvb, offset, 4, ett_rtps_product_version, NULL,
              "Product version: %d.%d.%d.%d", major, minor, release, revision);
    }
  } else if (vendor_id == RTPS_VENDOR_RTI_DDS_MICRO) {
    /* In Micro < 3.0.0 release and revision numbers are switched */
    if (major < 3) {
      revision = revision ^ release;
      release = revision ^ release;
      revision = revision ^ release;

      revision_offset = revision_offset ^ release_offset;
      release_offset = revision_offset ^ release_offset;
      revision_offset = revision_offset ^ release_offset;
    }
    if (revision != 0) {
      subtree = proto_tree_add_subtree_format(tree, tvb, offset, 4, ett_rtps_product_version, NULL,
        "Product version: %d.%d.%d.%d", major, minor, release, revision);
    } else {
      subtree = proto_tree_add_subtree_format(tree, tvb, offset, 4, ett_rtps_product_version, NULL,
        "Product version: %d.%d.%d", major, minor, release);
    }
  } else {
      return;
  }

  proto_tree_add_item(subtree, hf_rtps_param_product_version_major,
      tvb, offset, 1, ENC_NA);
  proto_tree_add_item(subtree, hf_rtps_param_product_version_minor,
      tvb, offset+1, 1, ENC_NA);
  /* If major revision is smaller than 5, release interpreted as char */
  if (vendor_id == RTPS_VENDOR_RTI_DDS && major < 5) {
    proto_tree_add_item(subtree, hf_rtps_param_product_version_release_as_char,
        tvb, offset + release_offset, 1, ENC_ASCII);
  } else {
    proto_tree_add_item(subtree, hf_rtps_param_product_version_release,
        tvb, offset + release_offset, 1, ENC_NA);
  }
  proto_tree_add_item(subtree, hf_rtps_param_product_version_revision,
      tvb, offset + revision_offset, 1, ENC_NA);
}

/* ------------------------------------------------------------------------- */
/* Insert in the protocol tree the next bytes interpreted as Sequence of
 * Strings.
 * The formatted buffer is: "string1", "string2", "string3", ...
 * Returns the new updated offset
 */
static gint rtps_util_add_seq_string(proto_tree *tree, tvbuff_t *tvb, gint offset,
                              const guint encoding, int hf_numstring,
                              int hf_string, const char *label) {
  guint32 size;
  gint32 i, num_strings;
  const char *retVal;
  proto_tree *string_tree;
  gint start;

  proto_tree_add_item_ret_int(tree, hf_numstring, tvb, offset, 4, encoding, &num_strings);
  offset += 4;

  if (num_strings == 0) {
    return offset;
  }

  start = offset;
  /* Create the string node with a fake string, the replace it later */
  string_tree = proto_tree_add_subtree(tree, tvb, offset, -1, ett_rtps_seq_string, NULL, label);

  for (i = 0; i < num_strings; ++i) {
    size = tvb_get_guint32(tvb, offset, encoding);

    retVal = (const char* )tvb_get_string_enc(wmem_packet_scope(), tvb, offset+4, size, ENC_ASCII);

    proto_tree_add_string_format(string_tree, hf_string, tvb, offset, size+4, retVal,
        "%s[%d]: %s", label, i, retVal);

    offset += (4 + ((size + 3) & 0xfffffffc));
  }

  proto_item_set_len(string_tree, offset - start);
  return offset;
}

/* ------------------------------------------------------------------------- */
/* Insert in the protocol tree the next bytes interpreted as Sequence of
 * longs.
 * The formatted buffer is: val1, val2, val3, ...
 * Returns the new updated offset
 */
static gint rtps_util_add_seq_ulong(proto_tree *tree, tvbuff_t *tvb, gint offset, int hf_item,
                        const guint encoding, int param_length _U_, const char *label) {
  guint32 num_elem;
  guint32 i;
  proto_tree *string_tree;

  num_elem = tvb_get_guint32(tvb, offset, encoding);
  offset += 4;

  /* Create the string node with an empty string, the replace it later */
  string_tree = proto_tree_add_subtree_format(tree, tvb, offset, num_elem*4,
                ett_rtps_seq_ulong, NULL, "%s (%d elements)", label, num_elem);

  for (i = 0; i < num_elem; ++i) {
    proto_tree_add_item(string_tree, hf_item, tvb, offset, 4, encoding);
    offset += 4;
  }

  return offset;
}

/* ------------------------------------------------------------------------- */
static const char *rtps_util_typecode_id_to_string(guint32 typecode_id) {
    switch(typecode_id) {
        case RTI_CDR_TK_ENUM:       return "enum";
        case RTI_CDR_TK_UNION:      return "union";
        case RTI_CDR_TK_STRUCT:     return "struct";
        case RTI_CDR_TK_LONG:       return "long";
        case RTI_CDR_TK_SHORT:      return "short";
        case RTI_CDR_TK_USHORT:     return "unsigned short";
        case RTI_CDR_TK_ULONG:      return "unsigned long";
        case RTI_CDR_TK_FLOAT:      return "float";
        case RTI_CDR_TK_DOUBLE:     return "double";
        case RTI_CDR_TK_BOOLEAN:    return "boolean";
        case RTI_CDR_TK_CHAR:       return "char";
        case RTI_CDR_TK_OCTET:      return "octet";
        case RTI_CDR_TK_LONGLONG:   return "longlong";
        case RTI_CDR_TK_ULONGLONG:  return "unsigned long long";
        case RTI_CDR_TK_LONGDOUBLE: return "long double";
        case RTI_CDR_TK_WCHAR:      return "wchar";
        case RTI_CDR_TK_WSTRING:    return "wstring";
        case RTI_CDR_TK_STRING:     return "string";
        case RTI_CDR_TK_SEQUENCE:   return "sequence";
        case RTI_CDR_TK_ARRAY:      return "array";
        case RTI_CDR_TK_ALIAS:      return "alias";
        case RTI_CDR_TK_VALUE:      return "valuetype";

        case RTI_CDR_TK_NULL:
        default:
            return "<unknown type>";
    }
}

/* ------------------------------------------------------------------------- */
/* Insert in the protocol tree the next bytes interpreted as typecode info
 * Returns the number of bytes parsed
 */
static gint rtps_util_add_typecode(proto_tree *tree, tvbuff_t *tvb, gint offset, const guint encoding,
                        int      indent_level, int is_pointer, guint16 bitfield, int is_key, const gint offset_begin,
                        char    *name,
                        int      seq_max_len,   /* -1 = not a sequence field */
                        guint32 *arr_dimension, /* if !NULL: array of 10 int */
                        int      ndds_40_hack) {
  const gint    original_offset = offset;
  guint32       tk_id;
  guint16       tk_size;
  unsigned int  i;
  char         *indent_string;
  gint          retVal;
  char          type_name[40];

    /* Structure of the typecode data:
     *  Offset   | Size  | Field                        | Notes
     * ----------|-------|------------------------------|---------------------
     *       ?   |    ?  | pad?                         |
     *       0   |    4  | RTI_CDR_TK_XXXXX             | 4 bytes aligned
     *       4   |    2  | length the struct            |
     */

  /* Calc indent string */
  indent_string = (char *)wmem_alloc(wmem_epan_scope(), (indent_level*2)+1);
  memset(indent_string, ' ', (indent_level*2)+1);
  indent_string[indent_level*2] = '\0';

  /* Gets TK ID */
  LONG_ALIGN(offset);
  tk_id = tvb_get_guint32(tvb, offset, encoding);
  offset += 4;

  /* Gets TK size */
  tk_size = tvb_get_guint16(tvb, offset, encoding);
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

  (void) g_strlcpy(type_name, rtps_util_typecode_id_to_string(tk_id), 40);

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
        guint32     struct_name_len;
        guint8      *struct_name;
        const char *discriminator_name      = "<unknown>"; /* for unions */
        char       *discriminator_enum_name = NULL;        /* for unions with enum discriminator */
        /*guint32 defaultIdx;*/ /* Currently is ignored */
        guint32     disc_id;                               /* Used temporarily to populate 'discriminator_name' */
        guint16     disc_size;                             /* Currently is ignored */
        guint32     disc_offset_begin, num_members, member_name_len;
        guint16     member_length;
        guint8     *member_name             = NULL;
        guint32     next_offset, field_offset_begin, member_label_count, discriminator_enum_name_length;
        gint32      member_label;
        guint       j;

        /* - - - - - - -      Union name      - - - - - - - */
        /* Pad-align */
        LONG_ALIGN(offset);

        /* Get structure name length */
        struct_name_len = tvb_get_guint32(tvb, offset, encoding);
        offset += 4;
        struct_name = tvb_get_string_enc(wmem_packet_scope(), tvb, offset, struct_name_len, ENC_ASCII);
        offset += struct_name_len;

        /* - - - - - - -      Default index      - - - - - - - */
        LONG_ALIGN(offset);
        /*defaultIdx = NEXT_guint32(tvb, offset, encoding);*/
        offset += 4;

        /* - - - - - - -      Discriminator type code     - - - - - - - */
        /* We don't recursively dissect everything, instead we just read the type */
        disc_id = tvb_get_guint32(tvb, offset, encoding);
        offset += 4;

        disc_size = tvb_get_guint16(tvb, offset, encoding);
        offset += 2;
        disc_offset_begin = offset;
        disc_id &= 0x7fffffff;
        discriminator_name = rtps_util_typecode_id_to_string(disc_id);
        if (disc_id == RTI_CDR_TK_ENUM) {
          /* Enums has also a name that we should print */
          LONG_ALIGN(offset);
          discriminator_enum_name_length = tvb_get_guint32(tvb, offset, encoding);
          discriminator_enum_name = tvb_get_string_enc(wmem_packet_scope(), tvb, offset+4, discriminator_enum_name_length, ENC_ASCII);
        }
        offset = disc_offset_begin + disc_size;
#if 0
        field_offset_begin = offset;
        offset += rtps_util_add_typecode(
                          tree,
                          tvb,
                          offset,
                          encoding,
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
        proto_tree_add_string_format(tree, hf_rtps_union, tvb, original_offset, retVal, struct_name, "%sunion %s (%s%s%s) {",
                    indent_string, struct_name, discriminator_name,
                    (discriminator_enum_name ? " " : ""),
                    (discriminator_enum_name ? discriminator_enum_name : ""));

        if (seq_max_len != -1) {
          /* We're dissecting a sequence of struct, bypass the seq definition */
          snprintf(type_name, 40, "%s", struct_name);
          break;
        }

        /* - - - - - - -      Number of members     - - - - - - - */
        LONG_ALIGN(offset);
        num_members = tvb_get_guint32(tvb, offset, encoding);
        offset += 4;

        /* - - - - - - -      <union_member>+     - - - - - - - */
        next_offset = offset;

        for (i = 0; i < num_members; ++i) {
          guint8  member_is_pointer;
          /* Safety: this theoretically should be the same already */
          field_offset_begin = offset = next_offset;

          SHORT_ALIGN(offset);

          /* member's length */
          member_length = tvb_get_guint16(tvb, offset, encoding);
          offset += 2;
          next_offset = offset + member_length;

          /* Name length */
          LONG_ALIGN(offset);
          member_name_len = tvb_get_guint32(tvb, offset, encoding);
          offset += 4;

          /* Name */
          member_name = tvb_get_string_enc(wmem_packet_scope(), tvb, offset, member_name_len, ENC_ASCII);
          offset += member_name_len;

          /* is Pointer ? */
          member_is_pointer = tvb_get_guint8(tvb, offset);
          offset++;

          /* Label count */
          LONG_ALIGN(offset);
          member_label_count = tvb_get_guint32(tvb, offset, encoding);
          offset += 4;

          for (j = 0; j < member_label_count; ++j) {
            proto_item* case_item;
            /* Label count */
            LONG_ALIGN(offset);
            member_label = tvb_get_guint32(tvb, offset, encoding);
            offset += 4;

            /* Add the entry of the union in the tree */
            case_item = proto_tree_add_uint_format(tree, hf_rtps_union_case, tvb, field_offset_begin, 1, member_label,
                                                    "%s  case %d:", indent_string, member_label);
            proto_item_set_len(case_item, retVal);
          }

          offset += rtps_util_add_typecode(tree, tvb, offset, encoding,
                    indent_level+2, member_is_pointer, 0, 0, field_offset_begin,
                    member_name, -1, NULL, ndds_40_hack);
        }
        /* Finally prints the name of the struct (if provided) */
        (void) g_strlcpy(type_name, "}", 40);
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
        gint8  *struct_name;
        guint32 struct_name_len, num_members;
        guint32 next_offset;
        const char *typecode_name;

        /* Pad-align */
        LONG_ALIGN(offset);

        /* Get structure name length */
        struct_name_len = tvb_get_guint32(tvb, offset, encoding);
        offset += 4;

        /* struct name */
        struct_name = tvb_get_string_enc(wmem_packet_scope(), tvb, offset, struct_name_len, ENC_ASCII);
        offset += struct_name_len;


        if (tk_id == RTI_CDR_TK_ENUM) {
          typecode_name = "enum";
        } else if (tk_id == RTI_CDR_TK_VALUE_PARAM) {
          /* guint16 type_modifier; */
          /* guint32 baseTypeCodeKind; */
          guint32 baseTypeCodeLength;

          /* Need to read the type modifier and the base type code */
          typecode_name = "<sparse type>";
          SHORT_ALIGN(offset);
          /* type_modifier = */ tvb_get_guint16(tvb, offset, encoding);
          offset += 2;

          LONG_ALIGN(offset);
          /* baseTypeCodeKind = */ tvb_get_guint32(tvb, offset, encoding);
          offset += 4;

          baseTypeCodeLength = tvb_get_guint32(tvb, offset, encoding);
          offset += 4;
          offset += baseTypeCodeLength;
        } else {
          typecode_name = "struct";
        }

        if (seq_max_len != -1) {
          /* We're dissecting a sequence of struct, bypass the seq definition */
          snprintf(type_name, 40, "%s", struct_name);
          break;
        }
        /* Prints it */
        proto_tree_add_string_format(tree, hf_rtps_struct, tvb, original_offset, retVal, struct_name,
                                     "%s%s %s {", indent_string, typecode_name, struct_name);

        /* PAD align */
        LONG_ALIGN(offset);

        /* number of members */
        num_members = tvb_get_guint32(tvb, offset, encoding);
        offset += 4;

        next_offset = offset;
        for (i = 0; i < num_members; ++i) {
          guint8  *member_name;
          guint32  member_name_len;
          guint16  member_length;
          guint32  field_offset_begin;

          /* Safety: this theoretically should be the same already */
          field_offset_begin = offset = next_offset;

          SHORT_ALIGN(offset);

          /* member's length */
          member_length = tvb_get_guint16(tvb, offset, encoding);
          offset += 2;
          next_offset = offset + member_length;

          /* Name length */
          LONG_ALIGN(offset);
          member_name_len = tvb_get_guint32(tvb, offset, encoding);
          offset += 4;

          /* Name */
          member_name = tvb_get_string_enc(wmem_packet_scope(), tvb, offset, member_name_len, ENC_ASCII);
          offset += member_name_len;

          if (tk_id == RTI_CDR_TK_ENUM) {
            /* ordinal number */
            guint32 ordinal_number;
            LONG_ALIGN(offset);
            ordinal_number = tvb_get_guint32(tvb, offset, encoding);
            offset += 4;

            proto_tree_add_string_format(tree, hf_rtps_member_name, tvb, field_offset_begin, (offset-field_offset_begin), member_name,
                                            "%s  %s = %d;", indent_string, member_name, ordinal_number);
          } else {
            /* Structs */
            guint16 member_bitfield;
            guint8  member_is_pointer;
            guint8  member_is_key;

            /* is Pointer ? */
            member_is_pointer = tvb_get_guint8(tvb, offset);
            offset++;

            /* Bitfield */
            SHORT_ALIGN(offset);
            member_bitfield = tvb_get_guint16(tvb, offset, encoding);
            offset += 2; /* pad will be added by typecode dissector */

            /* is Key ? */
            member_is_key = tvb_get_guint8(tvb, offset);
            offset++;

            offset += rtps_util_add_typecode(tree, tvb, offset, encoding,
                          indent_level+1, member_is_pointer, member_bitfield, member_is_key,
                          field_offset_begin, member_name, -1, NULL, ndds_40_hack);
          }
        }
        /* Finally prints the name of the struct (if provided) */
        (void) g_strlcpy(type_name, "}", 40);
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
        string_length = tvb_get_guint32(tvb, offset, encoding);
        offset += 4;
        snprintf(type_name, 40, "%s<%d>",
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
        seq_max_len2 = tvb_get_guint32(tvb, offset, encoding);
        offset += 4;

        /* Recursive decode seq typecode */
        /*offset += */rtps_util_add_typecode(tree, tvb, offset, encoding, indent_level,
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
        dim_max = tvb_get_guint32(tvb, offset, encoding);
        offset += 4;

        if (dim_max > MAX_ARRAY_DIMENSION) {
            /* We don't have a tree item to add expert info to... */
            dim_max = MAX_ARRAY_DIMENSION;
        }

        for (i = 0; i < MAX_ARRAY_DIMENSION; ++i) size[i] = 0;
        for (i = 0; i < dim_max; ++i) {
          size[i] = tvb_get_guint32(tvb, offset, encoding);
          offset += 4;
        }

        /* Recursive decode seq typecode */
        /*offset += */rtps_util_add_typecode(tree, tvb, offset, encoding,
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
        alias_name_length = tvb_get_guint32(tvb, offset, encoding);
        offset += 4;
        alias_name = tvb_get_string_enc(wmem_packet_scope(), tvb, offset, alias_name_length, ENC_ASCII);
        offset += alias_name_length;
        (void) g_strlcpy(type_name, alias_name, 40);
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
    case RTI_CDR_TK_VALUE_PARAM:
    case RTI_CDR_TK_VALUE: {
        /* Not fully dissected for now */
        /* Pad-align */
        guint32 value_name_len;
        gint8 *value_name;
        const char *type_id_name = "valuetype";
        LONG_ALIGN(offset);

        /* Get structure name length */
        value_name_len = tvb_get_guint32(tvb, offset, encoding);
        offset += 4;

        /* value name */
        value_name = tvb_get_string_enc(wmem_packet_scope(), tvb, offset, value_name_len, ENC_ASCII);
        offset += value_name_len;

        if (tk_id == RTI_CDR_TK_VALUE_PARAM) {
          type_id_name = "valueparam";
        }
        snprintf(type_name, 40, "%s '%s'", type_id_name, value_name);
        break;
    }
  } /* switch(tk_id) */

  /* Sequence print */
  if (seq_max_len != -1) {
    proto_tree_add_string_format(tree, hf_rtps_sequence, tvb, offset_begin, (offset-offset_begin), type_name,
                  "%ssequence<%s, %d> %s%s;%s", indent_string, type_name, seq_max_len,
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
    proto_tree_add_string_format(tree, hf_rtps_array, tvb, offset_begin, (offset-offset_begin), type_name,
                  "%s%s %s%s;%s", indent_string, type_name, name ? name : "",
                  wmem_strbuf_get_str(dim_str), is_key ? KEY_COMMENT : "");
    return retVal;
  }

  /* Bitfield print */
  if (bitfield != 0xffff && name != NULL && is_pointer == 0) {
    proto_tree_add_string_format(tree, hf_rtps_bitfield, tvb, offset_begin, (offset-offset_begin), type_name,
                  "%s%s %s:%d;%s", indent_string, type_name, name,
                  bitfield, is_key ? KEY_COMMENT : "");
    return retVal;
  }

  /* Everything else */
  proto_tree_add_string_format(tree, hf_rtps_datatype, tvb, offset_begin, (offset-offset_begin), type_name,
                  "%s%s%s%s%s;%s", indent_string, type_name,
                  name ? " " : "",
                  is_pointer ? "*" : "",
                  name ? name : "",
                  is_key ? KEY_COMMENT : "");
  return retVal;
}

static gint rtps_util_add_type_id(proto_tree *tree,
        tvbuff_t * tvb, gint offset, const guint encoding,
        gint zero, int hf_base, proto_item * append_info_item,
        guint64 * type_id) {
  proto_item * ti;
  guint16 short_number;
  guint64 longlong_number;
  int hf_type;
  short_number = tvb_get_guint16(tvb, offset, encoding);
  ti = proto_tree_add_item(tree, hf_rtps_type_object_type_id_disc, tvb, offset, 2, encoding);
  proto_item_set_hidden(ti);

  /* Here we choose the proper hf item to use */
  if (hf_base != -1) {
    if (short_number <= 13)
      hf_type = hf_rtps_type_object_base_primitive_type_id;
    else
      hf_type = hf_rtps_type_object_base_type;
  } else {
    if (short_number <= 13)
      hf_type = hf_rtps_type_object_primitive_type_id;
    else
      hf_type = hf_rtps_type_object_type_id;
  }

  offset += 2;
  if (short_number <= 13) {
    proto_tree_add_item(tree, hf_type, tvb, offset, 2, encoding);
    if (append_info_item) {
      proto_item_append_text(append_info_item, "(%s)",
                val_to_str(short_number, type_object_kind, "(0x%016x)"));
    }
    offset += 2;
  } else {
    ALIGN_ZERO(offset, 8, zero);
    longlong_number = tvb_get_guint64(tvb, offset, encoding);
    proto_tree_add_item(tree, hf_type, tvb, offset, 8, encoding);
    if (append_info_item) {
        proto_item_append_text(append_info_item, "(0x%016" PRIx64 ")", longlong_number);
    }
    offset += 8;
  }

  if (short_number <= 13) {
    if (type_id) {
      *type_id = short_number;
    }
  } else {
    if (type_id) {
      *type_id = longlong_number;
    }
  }
  return offset;
}

static gint rtps_util_add_type_annotation_usage(proto_tree *tree,
        tvbuff_t * tvb, gint offset, const guint encoding, gint zero) {
  guint32 long_number, i;
  guint16 short_number;
  offset = rtps_util_add_type_id(tree, tvb, offset, encoding, zero, -1, NULL, NULL);
  long_number = tvb_get_guint32(tvb, offset, encoding);
  offset += 4;
  for (i = 0; i < long_number; i++) {
    proto_tree_add_item(tree, hf_rtps_type_object_member_id, tvb, offset, 4, encoding);
    offset += 4;
    short_number = tvb_get_guint16(tvb, offset, encoding);
    proto_tree_add_item(tree, hf_rtps_type_object_annotation_value_d, tvb, offset, 2, encoding);
    offset += 2;
    /* There may be more additions in the future */
    switch (short_number) {
      case 4: /* UINT_16 */
        proto_tree_add_item(tree, hf_rtps_type_object_annotation_value_16, tvb, offset, 2, encoding);
        offset += 2;
        break;
    default:
        break;
    }

  }
  return offset;
}

static gint rtps_util_add_type_library_type(proto_tree *tree,
        tvbuff_t * tvb, gint offset, const guint encoding, dissection_info *info) {
  proto_tree * annotation_tree;
  guint32 member_id = 0, member_length = 0, long_number, i;
  gint offset_tmp;
  guint16 short_number;
  gchar * name = NULL;
  rtps_util_dissect_parameter_header(tvb, &offset, encoding, &member_id, &member_length);
  offset_tmp = offset;

  /* dissect property */
  short_number = tvb_get_guint16(tvb, offset_tmp, encoding);
  proto_tree_add_bitmask_value(tree, tvb, offset_tmp, hf_rtps_type_object_flags,
          ett_rtps_flags, TYPE_FLAG_FLAGS, short_number);
  if (info) {
    if (short_number & 0x02)
      info->extensibility = EXTENSIBILITY_MUTABLE;
    else if (short_number & 0x01)
      info->extensibility = EXTENSIBILITY_FINAL;
    else
      info->extensibility = EXTENSIBILITY_EXTENSIBLE;
  }
  offset_tmp += 2;
  if (info)
    offset_tmp = rtps_util_add_type_id(tree, tvb, offset_tmp, encoding, offset, -1, tree, &(info->type_id));
  else
    offset_tmp = rtps_util_add_type_id(tree, tvb, offset_tmp, encoding, offset, -1, tree, NULL);
  rtps_util_add_string(tree, tvb, offset_tmp, hf_rtps_type_object_type_property_name,
          encoding);
  long_number = tvb_get_guint32(tvb, offset_tmp, encoding);
  name = tvb_get_string_enc(wmem_packet_scope(), tvb, offset_tmp+4, long_number, ENC_ASCII);
  if (info)
    (void) g_strlcpy(info->member_name, name, long_number);

  proto_item_append_text(tree, " %s", name);
  offset += member_length;

  rtps_util_dissect_parameter_header(tvb, &offset, encoding, &member_id, &member_length);
  offset_tmp = offset;

  /* dissect annotation_seq */
  long_number = tvb_get_guint32(tvb, offset_tmp, encoding);
  annotation_tree = proto_tree_add_subtree_format(tree, tvb, offset_tmp, member_length,
            ett_rtps_type_annotation_usage_list, NULL, "Annotation Usage Member List (%d elements)",
            long_number);
  offset_tmp += 4;
  for (i = 0; i < long_number ; i++) {
      offset_tmp = rtps_util_add_type_annotation_usage(annotation_tree, tvb, offset_tmp,
              encoding, offset);
  }
  offset += member_length;

  return offset;
}

static void rtps_util_add_type_element_enumeration(proto_tree *tree,
        tvbuff_t * tvb, gint offset, const guint encoding, dissection_info * info) {
  proto_tree * enumerated_constant;
  guint32 member_id = 0, member_length = 0;
  guint32 long_number, i;
  gint enum_size, offset_tmp;

  offset = rtps_util_add_type_library_type(tree, tvb, offset, encoding, info);

  rtps_util_dissect_parameter_header(tvb, &offset, encoding, &member_id, &member_length);
  /* dissect Bound */
  proto_tree_add_item(tree, hf_rtps_type_object_bound, tvb, offset, 4, encoding);
  offset += member_length;

  rtps_util_dissect_parameter_header(tvb, &offset, encoding, &member_id, &member_length);
  /* dissect constant seq */
  offset_tmp = offset;
  long_number = tvb_get_guint32(tvb, offset_tmp, encoding);
  offset_tmp += 4;
  for (i = 0; i < long_number; i++) {
    gchar * name = NULL;
    guint32 size, value;
    enum_size = offset_tmp;
    size = tvb_get_guint32(tvb, offset_tmp + 4, encoding);
    name = tvb_get_string_enc(wmem_packet_scope(), tvb, offset_tmp + 8, size, ENC_ASCII);
    value = tvb_get_guint32(tvb, offset_tmp, encoding);
    enumerated_constant = proto_tree_add_subtree_format(tree, tvb, offset_tmp, 0,
          ett_rtps_type_enum_constant, NULL, "%s (%u)", name, value);
    proto_tree_add_item(enumerated_constant, hf_rtps_type_object_enum_constant_value, tvb, offset_tmp, 4, encoding);
    offset_tmp += 4;
    offset_tmp = rtps_util_add_string(enumerated_constant, tvb, offset_tmp, hf_rtps_type_object_enum_constant_name, encoding);
    proto_item_set_len(enumerated_constant, offset_tmp - enum_size);
  }

  info->num_elements = 0;
}

static void rtps_util_add_type_element_sequence(proto_tree *tree,
        tvbuff_t * tvb, gint offset, const guint encoding, dissection_info * info) {
  guint32 member_id = 0, member_length = 0;
  gint zero_alignment;
  offset = rtps_util_add_type_library_type(tree, tvb, offset, encoding, info);

  rtps_util_dissect_parameter_header(tvb, &offset, encoding, &member_id, &member_length);
  zero_alignment = offset;
  rtps_util_add_type_id(tree, tvb, offset, encoding, zero_alignment, -1 , NULL, &(info->base_type_id));
  offset += member_length;
  rtps_util_dissect_parameter_header(tvb, &offset, encoding, &member_id, &member_length);
  proto_tree_add_item(tree, hf_rtps_type_object_element_shared, tvb, offset, 1, encoding);
  offset += member_length;
  rtps_util_dissect_parameter_header(tvb, &offset, encoding, &member_id, &member_length);
  /* dissect Bound */
  proto_tree_add_item(tree, hf_rtps_type_object_bound, tvb, offset, 4, encoding);
  if (info)
    info->bound = tvb_get_gint32(tvb, offset, encoding);
}

static void rtps_util_add_type_element_string(proto_tree *tree,
        tvbuff_t * tvb, gint offset, const guint encoding, dissection_info * info _U_) {
  guint32 member_id = 0, member_length = 0;
  gint zero_alignment;
  offset = rtps_util_add_type_library_type(tree, tvb, offset, encoding, info);

  rtps_util_dissect_parameter_header(tvb, &offset, encoding, &member_id, &member_length);
  zero_alignment = offset;
  rtps_util_add_type_id(tree, tvb, offset, encoding, zero_alignment, -1, NULL, NULL);
  offset += member_length;
  rtps_util_dissect_parameter_header(tvb, &offset, encoding, &member_id, &member_length);
  proto_tree_add_item(tree, hf_rtps_type_object_element_shared, tvb, offset, 1, encoding);
  offset += member_length;
  rtps_util_dissect_parameter_header(tvb, &offset, encoding, &member_id, &member_length);
  /* dissect Bound */
  proto_tree_add_item(tree, hf_rtps_type_object_bound, tvb, offset, 4, encoding);
  offset += member_length;
}

static void rtps_util_add_type_element_array(proto_tree *tree,
        tvbuff_t * tvb, gint offset, const guint encoding, dissection_info * info _U_) {
  proto_tree * bound_tree;
  guint32 member_id = 0, member_length = 0;
  guint32 long_number, i;
  gint zero_alignment, offset_tmp;
  offset = rtps_util_add_type_library_type(tree, tvb, offset, encoding, info);

  /* Dissect Collection Type */
  rtps_util_dissect_parameter_header(tvb, &offset, encoding, &member_id, &member_length);
  zero_alignment = offset;
  rtps_util_add_type_id(tree, tvb, offset, encoding, zero_alignment, -1, NULL, &(info->base_type_id));
  offset += member_length;
  rtps_util_dissect_parameter_header(tvb, &offset, encoding, &member_id, &member_length);
  proto_tree_add_item(tree, hf_rtps_type_object_element_shared, tvb, offset, 1, encoding);
  offset += member_length;
  rtps_util_dissect_parameter_header(tvb, &offset, encoding, &member_id, &member_length);

  /* dissect Bound sequence */

  offset_tmp = offset;
  long_number = tvb_get_guint32(tvb, offset_tmp, encoding);
  bound_tree = proto_tree_add_subtree_format(tree, tvb, offset_tmp, member_length,
              ett_rtps_type_bound_list, NULL, "Bounds (%d elements)",
              long_number);
  offset_tmp += 4;
  for (i = 0; i < long_number ; i++) {
    proto_tree_add_item(bound_tree, hf_rtps_type_object_bound, tvb, offset_tmp, 4, encoding);
    if (info) info->bound = tvb_get_gint32(tvb, offset_tmp, encoding);
    if (info) info->num_elements = tvb_get_gint32(tvb, offset_tmp, encoding);

    offset_tmp += 4;
  }
}

static void rtps_util_add_type_element_alias(proto_tree *tree,
        tvbuff_t * tvb, gint offset, const guint encoding, dissection_info * info) {
  guint32 member_id = 0, member_length = 0;
  offset = rtps_util_add_type_library_type(tree, tvb, offset, encoding, info);

  /* dissect base_type */
  rtps_util_dissect_parameter_header(tvb, &offset, encoding, &member_id, &member_length);
  rtps_util_add_type_id(tree, tvb, offset, encoding, offset, hf_rtps_type_object_base_type, NULL, &(info->base_type_id));
}

static gint rtps_util_add_type_member(proto_tree *tree,
        tvbuff_t * tvb, gint offset, const guint encoding,
        dissection_info * info, dissection_element * member_object) {
  proto_tree * member_property, *annotation_tree;
  guint32 member_id = 0, member_length = 0;
  guint32 long_number, i;
  guint16 short_number;
  guint64 member_type_id;
  gint offset_tmp;
  gchar * name = NULL;

  member_property = proto_tree_add_subtree(tree, tvb, offset, 0,
                ett_rtps_type_element, NULL, "Member Property");
  rtps_util_dissect_parameter_header(tvb, &offset, encoding, &member_id, &member_length);
  offset_tmp = offset;
  short_number = tvb_get_guint16(tvb, offset_tmp, encoding);
  proto_tree_add_bitmask_value(member_property, tvb, offset_tmp, hf_rtps_type_object_flags,
          ett_rtps_flags, MEMBER_FLAGS, short_number);
  if (member_object) member_object->flags = short_number;
  offset_tmp += 2;
  ALIGN_ZERO(offset_tmp, 4, offset);
  proto_tree_add_item(member_property, hf_rtps_type_object_member_id, tvb, offset_tmp, 4, encoding);
  member_id = tvb_get_guint32(tvb, offset_tmp, encoding);
  offset_tmp += 4;
  offset_tmp = rtps_util_add_type_id(member_property, tvb, offset_tmp, encoding,
          offset, -1, tree, &member_type_id);
  rtps_util_add_string(member_property, tvb, offset_tmp, hf_rtps_type_object_name, encoding);
  long_number = tvb_get_guint32(tvb, offset_tmp, encoding);
  name = tvb_get_string_enc(wmem_packet_scope(), tvb, offset_tmp+4, long_number, ENC_ASCII);
  proto_item_append_text(tree, " %s (ID: %d)", name, member_id);
  if (member_object) {
    member_object->member_id = member_id;
    (void) g_strlcpy(member_object->member_name, name, long_number < 256 ? long_number : 256);
    member_object->type_id = member_type_id;
  }
  if (info && info->extensibility == EXTENSIBILITY_MUTABLE) {
      mutable_member_mapping * mutable_mapping = NULL;
      mutable_mapping = wmem_new(wmem_file_scope(), mutable_member_mapping);
      (void) g_strlcpy(mutable_mapping->member_name, name, long_number < 256 ? long_number : 256);
      mutable_mapping->struct_type_id = info->type_id;
      mutable_mapping->member_type_id = member_type_id;
      mutable_mapping->member_id = member_id;
      mutable_mapping->key = (mutable_mapping->struct_type_id + mutable_mapping->struct_type_id * mutable_mapping->member_id);
      proto_item_append_text(tree, "(Inserted 0x%016" PRIx64 " from 0x%016" PRIx64 ")", mutable_mapping->key, mutable_mapping->struct_type_id);
      wmem_map_insert(mutable_member_mappings, &(mutable_mapping->key), (void *) mutable_mapping);

  }

  offset += member_length;

  rtps_util_dissect_parameter_header(tvb, &offset, encoding, &member_id, &member_length);
  offset_tmp = offset;
  long_number = tvb_get_guint32(tvb, offset_tmp, encoding);
  annotation_tree = proto_tree_add_subtree_format(tree, tvb, offset_tmp, member_length,
              ett_rtps_type_annotation_usage_list, NULL, "Annotation Usage Member List (%d elements)",
              long_number);
  offset_tmp += 4;
  for (i = 0; i < long_number ; i++) {
        offset_tmp = rtps_util_add_type_annotation_usage(annotation_tree, tvb, offset_tmp,
                encoding, offset);
  }
  offset += member_length;

  long_number = tvb_get_guint32(tvb, offset, encoding);
  if ((long_number & PID_LIST_END) == PID_LIST_END) {
    offset += 4;
  }

  return offset;
}

static gint rtps_util_add_type_union_member(proto_tree *tree,
        tvbuff_t * tvb, gint offset, const guint encoding, guint64 union_type_id,
        gboolean is_discriminator, dissection_info * info _U_) {
  proto_tree * labels;
  gint long_number, i;
  gint offset_tmp;
  guint32 member_id = 0, member_length = 0;
  dissection_element object;
  offset = rtps_util_add_type_member(tree, tvb, offset, encoding, NULL, &object); //&(info->elements[i])

  rtps_util_dissect_parameter_header(tvb, &offset, encoding, &member_id, &member_length);
  offset_tmp = offset;

  long_number = tvb_get_guint32(tvb, offset_tmp, encoding);

  labels = proto_tree_add_subtree_format(tree, tvb, offset_tmp, member_length,
          ett_rtps_type_enum_constant, NULL, "Labels (%u elements)", long_number);
  offset_tmp += 4;
  if ((object.flags & 8) == 8) {
    union_member_mapping * mapping = NULL;

    mapping = wmem_new(wmem_file_scope(), union_member_mapping);
    (void) g_strlcpy(mapping->member_name, object.member_name, 256);
    mapping->member_type_id = object.type_id;
    mapping->discriminator = HASHMAP_DISCRIMINATOR_CONSTANT;
    mapping->union_type_id = union_type_id + mapping->discriminator;

    wmem_map_insert(union_member_mappings, &(mapping->union_type_id), (void *) mapping);
    proto_item_append_text(labels, " Added mapping for discriminator (0x%016" PRIx64 ") name = %s",
    mapping->union_type_id, mapping->member_name);
  }
  if (is_discriminator) {
    union_member_mapping * mapping = NULL;

    mapping = wmem_new(wmem_file_scope(), union_member_mapping);
    (void) g_strlcpy(mapping->member_name, object.member_name, 256);
    mapping->member_type_id = object.type_id;
    mapping->discriminator = -1;
    mapping->union_type_id = union_type_id + mapping->discriminator;

    wmem_map_insert(union_member_mappings, &(mapping->union_type_id), (void *) mapping);
    proto_item_append_text(labels, " Added mapping for discriminator (0x%016" PRIx64 ") name = %s",
    mapping->union_type_id, mapping->member_name);
  }
  for (i = 0; i < long_number; i++) {
    proto_item * ti;
    union_member_mapping * mapping = NULL;
    guint32 discriminator_case;

    mapping = wmem_new(wmem_file_scope(), union_member_mapping);

    discriminator_case = tvb_get_guint32(tvb, offset_tmp, encoding);
    ti = proto_tree_add_item(labels, hf_rtps_type_object_union_label, tvb, offset_tmp, 4, encoding);
    offset_tmp += 4;

    (void) g_strlcpy(mapping->member_name, object.member_name, 256);
    mapping->member_type_id = object.type_id;
    mapping->discriminator = discriminator_case;
    mapping->union_type_id = union_type_id + discriminator_case;

    wmem_map_insert(union_member_mappings, &(mapping->union_type_id), (void *) mapping);
    proto_item_append_text(ti, " Added mapping for discriminator (0x%016" PRIx64 ") name = %s",
        mapping->union_type_id, mapping->member_name);
  }

  offset += member_length;
  long_number = tvb_get_guint32(tvb, offset_tmp, encoding);

  if ((long_number & PID_LIST_END) == PID_LIST_END) {
    offset += 4;
  }

  return offset;
}

static void rtps_util_add_type_element_union(proto_tree *tree,
        tvbuff_t * tvb, gint offset, const guint encoding, dissection_info * info) {
  proto_tree * members;
  guint32 member_id = 0, member_length = 0;
  guint32 long_number, i;
  gint offset_tmp;
  offset = rtps_util_add_type_library_type(tree, tvb, offset, encoding, info);

  rtps_util_dissect_parameter_header(tvb, &offset, encoding, &member_id, &member_length);
  offset_tmp = offset;

  long_number = tvb_get_guint32(tvb, offset_tmp, encoding);
  members = proto_tree_add_subtree(tree, tvb, offset_tmp, -1,
          ett_rtps_type_enum_constant, NULL, "Members");

  offset_tmp += 4;

  for (i = 0; i < long_number; i++) {
    proto_tree * member = NULL;
    gint offset_member = offset_tmp;
    member = proto_tree_add_subtree(members, tvb, offset_tmp, 0,
          ett_rtps_type_enum_constant, NULL, "Member");
    offset_tmp = rtps_util_add_type_union_member(member, tvb, offset_tmp, encoding,
        info->type_id, (i == 0), info);
    proto_item_set_len(member, offset_tmp - offset_member);
  }

  long_number = tvb_get_guint32(tvb, offset_tmp, encoding);
  if ((long_number & PID_LIST_END) == PID_LIST_END) {
    offset_tmp += 4;
  }
  proto_item_set_len(members, offset_tmp - offset);
}

static void rtps_util_add_type_element_struct(proto_tree *tree,
        tvbuff_t * tvb, gint offset, const guint encoding, dissection_info * info) {
  proto_tree * member;
  guint32 member_id = 0, member_length = 0;
  guint32 long_number, i, max_elements = 0;
  gint offset_tmp, member_size;

  offset = rtps_util_add_type_library_type(tree, tvb, offset, encoding, info);

  /* dissect base_type */
  rtps_util_dissect_parameter_header(tvb, &offset, encoding, &member_id, &member_length);
  offset = rtps_util_add_type_id(tree, tvb, offset, encoding, offset, hf_rtps_type_object_base_type, NULL, &(info->base_type_id));

  rtps_util_dissect_parameter_header(tvb, &offset, encoding, &member_id, &member_length);
  /* dissect seq_member*/

  offset_tmp = offset;
  long_number = tvb_get_guint32(tvb, offset_tmp, encoding);

  offset_tmp += 4;

  max_elements = (enable_max_data_type_elements)
          ? MIN(long_number, rtps_max_data_type_elements)
          : long_number;

  if (info) {
      info->elements = (dissection_element*)wmem_alloc0(
            wmem_file_scope(),
            sizeof(dissection_element) * max_elements);
  }
  for (i = 0; i < max_elements; i++) {
      member_size = offset_tmp;
      member = proto_tree_add_subtree(tree, tvb, offset_tmp, 0,
          ett_rtps_type_enum_constant, NULL, "");
      if (info && info->elements)
        offset_tmp = rtps_util_add_type_member(member, tvb, offset_tmp, encoding, info, &(info->elements[i]));
      else
        offset_tmp = rtps_util_add_type_member(member, tvb, offset_tmp, encoding, NULL, NULL);
      proto_item_set_len(member, offset_tmp - member_size);
  }
  if (i < long_number) {
      proto_tree_add_subtree_format(
          tree,
          tvb,
          0,
          0,
          ett_rtps_info_remaining_items,
          NULL,
          DISSECTION_INFO_REMAINING_ELEMENTS_STR_d,
          long_number - i);
  }
  if (info)
    info->num_elements = long_number;
}

static void rtps_util_add_type_library(proto_tree *tree, packet_info * pinfo,
        tvbuff_t * tvb, gint offset, const guint encoding, guint32 size);

static void rtps_util_add_type_element_module(proto_tree *tree, packet_info * pinfo,
        tvbuff_t * tvb, gint offset, const guint encoding) {
  guint32 long_number;
  gchar * name = NULL;
  long_number = tvb_get_guint32(tvb, offset, encoding);
  name = tvb_get_string_enc(wmem_packet_scope(), tvb, offset+4, long_number, ENC_ASCII);
  proto_item_set_text(tree, "module %s", name);
  offset = rtps_util_add_string(tree, tvb, offset, hf_rtps_type_object_element_module_name, encoding);
  rtps_util_add_type_library(tree, pinfo, tvb, offset, encoding, -1);
}

static gint rtps_util_add_type_library_element(proto_tree *tree, packet_info * pinfo,
        tvbuff_t * tvb, gint offset, const guint encoding) {
  proto_tree * element_tree;
  guint32 long_number;
  guint32 member_id = 0, member_length = 0;
  gint initial_offset = offset;
  dissection_info * info;
  gboolean add_info = TRUE;

  info = wmem_new(wmem_file_scope(), dissection_info);
  info->elements = NULL;

  rtps_util_dissect_parameter_header(tvb, &offset, encoding, &member_id, &member_length);
  long_number = tvb_get_guint32(tvb, offset, encoding);
  info->member_kind = long_number;

  element_tree = proto_tree_add_subtree(tree, tvb, offset, 0,
                    ett_rtps_type_element, NULL, "");
  offset += member_length;
  rtps_util_dissect_parameter_header(tvb, &offset, encoding, &member_id, &member_length);
  proto_item_set_len(element_tree, member_length + offset - initial_offset);
  switch (long_number) {
    case RTI_CDR_TYPE_OBJECT_TYPE_KIND_ENUMERATION_TYPE: /*ENUMERATION */
      rtps_util_add_type_element_enumeration(element_tree, tvb, offset, encoding, info);
      break;
    case RTI_CDR_TYPE_OBJECT_TYPE_KIND_ALIAS_TYPE: /* ALIAS */
      rtps_util_add_type_element_alias(element_tree, tvb, offset, encoding, info);
      break;
    case RTI_CDR_TYPE_OBJECT_TYPE_KIND_ARRAY_TYPE: /* ARRAY */
      rtps_util_add_type_element_array(element_tree, tvb, offset, encoding, info);
      break;
    case RTI_CDR_TYPE_OBJECT_TYPE_KIND_SEQUENCE_TYPE: /* SEQUENCE */
      rtps_util_add_type_element_sequence(element_tree, tvb, offset, encoding, info);
      break;
    case RTI_CDR_TYPE_OBJECT_TYPE_KIND_STRING_TYPE: /* STRING : COLLECTION */
      rtps_util_add_type_element_string(element_tree, tvb, offset, encoding, info);
      break;
    case RTI_CDR_TYPE_OBJECT_TYPE_KIND_UNION_TYPE:
      rtps_util_add_type_element_union(element_tree, tvb, offset, encoding, info);
      break;
    case RTI_CDR_TYPE_OBJECT_TYPE_KIND_STRUCTURE_TYPE: /* STRUCT */
      rtps_util_add_type_element_struct(element_tree, tvb, offset, encoding, info);
      break;
    case RTI_CDR_TYPE_OBJECT_TYPE_KIND_MODULE:
      /* This does *not* fill in the info structure, so do *not* add it. */
      add_info = FALSE;
      rtps_util_add_type_element_module(element_tree, pinfo, tvb, offset, encoding);
      break;
    default:
      /* We have *not* filled in the info structure, so do *not* add it. */
      add_info = FALSE;
      proto_item_append_text(element_tree, "Kind: %u", long_number);
      proto_tree_add_item(element_tree, hf_rtps_type_object_element_raw, tvb, offset,
                          member_length, encoding);
      break;
  }
  offset += member_length;
  LONG_ALIGN(offset);
  long_number = tvb_get_guint32(tvb, offset, encoding);
  if ((long_number & PID_LIST_END) != PID_LIST_END) {
      expert_add_info_format(pinfo, element_tree, &ei_rtps_parameter_value_invalid,
              "Now it should be PID_LIST_END and it is not"); \
  }
  offset += 4;
  proto_item_set_len(element_tree, offset - initial_offset);

  if (add_info) {
    wmem_map_insert(dissection_infos, &(info->type_id), (void *) info);
  }

  return offset;
}

static void rtps_util_add_type_library(proto_tree *tree, packet_info * pinfo,
        tvbuff_t * tvb, gint offset, const guint encoding, guint32 size) {
  proto_tree * library_tree;
  guint32 long_number, i;
  long_number = tvb_get_guint32(tvb, offset, encoding);
  library_tree = proto_tree_add_subtree_format(tree, tvb, offset, size,
                    ett_rtps_type_library, NULL, "Type Library (%d elements)", long_number);
  offset += 4;
  for (i = 0; i < long_number; i++) {
      offset = rtps_util_add_type_library_element(library_tree, pinfo, tvb,
              offset, encoding);
  }
}

static void rtps_util_add_typeobject(proto_tree *tree, packet_info * pinfo,
        tvbuff_t * tvb, gint offset, const guint encoding, guint32 size,
        type_mapping * type_mapping_object ) {
  proto_tree * typeobject_tree;
  gint offset_tmp = 0;
  guint32 member_id = 0, member_length = 0;
  guint32 long_number;
  guint64 type_id;

  typeobject_tree = proto_tree_add_subtree(tree, tvb, offset, size,
          ett_rtps_type_object, NULL, "Type Object");
  /* --- This is the standard parameterized serialization --- */
  /*                       TypeLibrary                        */
  rtps_util_dissect_parameter_header(tvb, &offset, encoding, &member_id, &member_length);
  offset_tmp = offset;
  /* Dissect the member */
  rtps_util_add_type_library(typeobject_tree, pinfo, tvb, offset_tmp, encoding, member_length);
  offset += member_length;
  /*                    End TypeLibrary                       */

  /*                         _TypeId                          */
  rtps_util_dissect_parameter_header(tvb, &offset, encoding, &member_id, &member_length);
  offset_tmp = offset;
  /* Dissect the member. In this case, the typeid is an union with a short
   * as a discriminator*/
  rtps_util_add_type_id(typeobject_tree, tvb, offset_tmp, encoding, offset, -1, NULL, &type_id);
  if (type_mapping_object) type_mapping_object->type_id = type_id;
  offset = offset + member_length;
  /*                      End _TypeId                          */

  long_number = tvb_get_guint32(tvb, offset, encoding);
  if ((long_number & PID_LIST_END) != PID_LIST_END) {
      expert_add_info_format(pinfo, typeobject_tree, &ei_rtps_parameter_value_invalid,
              "This should be PID_LIST_END and it is not"); \
  }

}

#ifdef HAVE_ZLIB
static void rtps_add_zlib_compressed_typeobject(proto_tree *tree, packet_info * pinfo,
  tvbuff_t * tvb, gint offset, const guint encoding, guint compressed_size,
  guint decompressed_size, type_mapping * type_mapping_object) {

  tvbuff_t *decompressed_data_child_tvb;
  tvbuff_t *compressed_type_object_subset;
  proto_tree *decompressed_type_object_subtree;

  compressed_type_object_subset = tvb_new_subset_length(tvb, offset, decompressed_size);
  decompressed_data_child_tvb = tvb_child_uncompress(tvb, compressed_type_object_subset, 0, compressed_size);
  if (decompressed_data_child_tvb) {
    decompressed_type_object_subtree = proto_tree_add_subtree(tree, decompressed_data_child_tvb,
      0, 0, ett_rtps_decompressed_type_object, NULL, "[Uncompressed type object]");
    rtps_util_add_typeobject(decompressed_type_object_subtree, pinfo,
      decompressed_data_child_tvb, 0, encoding, decompressed_size, type_mapping_object);
  }
  else {
    proto_tree_add_subtree(tree, compressed_type_object_subset,
      0, 0, ett_rtps_decompressed_type_object, NULL, "[Failed to decompress type object]");
  }
}
#else
static void rtps_add_zlib_compressed_typeobject(proto_tree *tree _U_, packet_info * pinfo _U_,
  tvbuff_t * tvb _U_, gint offset _U_, const guint encoding _U_, guint compressed_size _U_,
  guint decompressed_size _U_, type_mapping * type_mapping_object _U_)
{
}
#endif

/* ------------------------------------------------------------------------- */
/* Insert in the protocol tree the next bytes interpreted as Sequence of
 * Octets.
 * The formatted buffer is: [ 0x01, 0x02, 0x03, 0x04, ...]
 * The maximum number of elements displayed is 10, after that a '...' is
 * inserted.
 */
static gint rtps_util_add_seq_octets(proto_tree *tree, packet_info *pinfo, tvbuff_t *tvb,
                              gint offset, const guint encoding, int param_length, int hf_id) {
  guint32 seq_length;
  proto_item *ti;

  ti = proto_tree_add_item_ret_uint(tree, hf_rtps_sequence_size, tvb, offset, 4, encoding, &seq_length);

  offset += 4;
  /* param length -1 means not specified */
  if (param_length != -1 && param_length < 4 + (int)seq_length) {
    expert_add_info_format(pinfo, ti, &ei_rtps_parameter_value_invalid, "ERROR: Parameter value too small");
    return offset + seq_length;
  }

  if (seq_length) {
    proto_tree_add_item(tree, hf_id, tvb, offset, seq_length, ENC_NA);
  }

  return offset + seq_length;
}

static gint rtps_util_add_data_holder(proto_tree *tree, tvbuff_t * tvb, packet_info * pinfo,
        gint offset, const guint encoding, gint seq_index, gint alignment_zero) {
  proto_tree * data_holder_tree, * properties_tree, * property_tree;
  proto_item * tii, * ti, * data_holder;
  guint32 seq_size, i;
  gint offset_tmp, data_holder_begin;

  data_holder_tree = proto_tree_add_subtree_format(tree, tvb, offset,
      -1, ett_rtps_data_holder, &data_holder, "Data Holder [%d]", seq_index);
  data_holder_begin = offset;
  offset = rtps_util_add_string(data_holder_tree, tvb, offset,
          hf_rtps_pgm_data_holder_class_id, encoding);
  LONG_ALIGN_ZERO(offset, alignment_zero);

  offset_tmp = offset;
  properties_tree = proto_tree_add_subtree_format(data_holder_tree, tvb, offset,
      -1, ett_rtps_data_holder_properties, &tii, "String Properties");
  seq_size = tvb_get_guint32(tvb, offset, encoding);
  offset += 4;
  for(i = 0; i < seq_size; i++) {
    gint local_offset = offset;
    property_tree = proto_tree_add_subtree_format(properties_tree, tvb, offset,
             -1, ett_rtps_property_tree, &ti, "Property [%d]", i);
    offset = rtps_util_add_string(property_tree, tvb, offset,
                    hf_rtps_property_name, encoding);
    offset = rtps_util_add_string(property_tree, tvb, offset,
                    hf_rtps_property_value, encoding);
    proto_item_set_len(ti, offset - local_offset);
  }
  proto_item_set_len(tii, offset - offset_tmp);

  offset_tmp = offset;
  properties_tree = proto_tree_add_subtree_format(data_holder_tree, tvb, offset,
             -1, ett_rtps_data_holder_properties, &tii, "Binary Properties");
  seq_size = tvb_get_guint32(tvb, offset, encoding);
  offset += 4;
  for(i = 0; i < seq_size; i++) {
    gint local_offset = offset;
    LONG_ALIGN(offset);
    property_tree = proto_tree_add_subtree_format(properties_tree, tvb, offset,
                    -1, ett_rtps_property_tree, &ti, "Property [%d]", i);
    offset = rtps_util_add_string(property_tree, tvb, offset,
                    hf_rtps_property_name, encoding);
    offset = rtps_util_add_seq_octets(property_tree, pinfo, tvb, offset,
                    encoding, -1, hf_rtps_param_user_data);
    proto_item_set_len(ti, offset - local_offset);
  }
  proto_item_set_len(tii, offset - offset_tmp);
  proto_item_set_len(data_holder, offset - offset_tmp);

  proto_item_set_len(data_holder, offset - data_holder_begin);
  return offset;
}

static gint rtps_util_add_data_holder_seq(proto_tree *tree, tvbuff_t * tvb,
        packet_info * pinfo, gint offset, const guint encoding, gint alignment_zero) {
  proto_tree * data_holder_seq_tree;
  proto_item * ti;
  guint32 seq_length;
  guint32 i;

  data_holder_seq_tree = proto_tree_add_subtree(tree, tvb, offset,
          -1, ett_rtps_data_holder_seq, &ti, "Data Holder Sequence");
  seq_length = tvb_get_guint32(tvb, offset, encoding);
  offset += 4;
  for(i = 0; i < seq_length; i++) {
    offset = rtps_util_add_data_holder(data_holder_seq_tree, tvb, pinfo, offset,
                encoding, i, alignment_zero);
  }
  return offset;
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
                        tvbuff_t *tvb,
                        gint       offset,
                        const guint encoding,
                        const char *label,
                        gboolean show_analysis) {
  gint32 num_bits;
  guint32 data;
  wmem_strbuf_t *temp_buff = wmem_strbuf_new_label(wmem_packet_scope());
  wmem_strbuf_t *analysis_buff = wmem_strbuf_new_label(wmem_packet_scope());
  gint i, j, idx;
  gchar *last_one;
  proto_item *ti = NULL, *ti_tree = NULL;
  proto_tree *bitmap_tree;
  const gint original_offset = offset;
  guint32 datamask;
  guint64 first_seq_number;
  gboolean first_nack = TRUE;

  bitmap_tree = proto_tree_add_subtree(tree, tvb, original_offset, offset-original_offset,
          ett_rtps_bitmap, &ti_tree, label);

  /* Bitmap base sequence number */
  first_seq_number = rtps_util_add_seq_number(bitmap_tree, tvb, offset, encoding, "bitmapBase");
  offset += 8;

  /* Reads the bitmap size */
  proto_tree_add_item_ret_uint(bitmap_tree, hf_rtps_bitmap_num_bits, tvb, offset, 4, encoding, &num_bits);
  offset += 4;
  /* bitmap base 0 means that this is a preemptive ACKNACK */
  if (first_seq_number == 0 && show_analysis) {
    ti = proto_tree_add_uint_format(bitmap_tree, hf_rtps_acknack_analysis, tvb, 0, 0,
        1, "Acknack Analysis: Preemptive ACKNACK");
    proto_item_set_generated(ti);
  }

  if (first_seq_number > 0 && num_bits == 0 && show_analysis) {
    ti = proto_tree_add_uint_format(bitmap_tree, hf_rtps_acknack_analysis, tvb, 0, 0,
            2, "Acknack Analysis: Expecting sample %" PRIu64, first_seq_number);
    proto_item_set_generated(ti);
  }

  if (num_bits > 0 && show_analysis) {
    ti = proto_tree_add_uint_format(bitmap_tree, hf_rtps_acknack_analysis, tvb, 0, 0,
            3, "Acknack Analysis: Lost samples");
    proto_item_set_generated(ti);
  }

  /* Reads the bits (and format the print buffer) */
  idx = 0;
  for (i = 0; i < num_bits; i += 32) {
    data = tvb_get_guint32(tvb, offset, encoding);
    offset += 4;
    for (j = 0; j < 32; ++j) {
      datamask = (1U << (31-j));
      wmem_strbuf_append_c(temp_buff, ((data & datamask) == datamask) ? '1':'0');
      if ((data & datamask) == datamask) {
        proto_item_append_text(ti,
                first_nack ? " %" PRIu64 : ", %" PRIu64,
                first_seq_number + idx);
        first_nack = FALSE;
      }
      ++idx;
      if ((idx >= num_bits) || (wmem_strbuf_get_len(temp_buff) >= (ITEM_LABEL_LENGTH - 1))) {
        break;
      }
    }
  }

  /* removes all the ending '0' */
  last_one = strrchr(wmem_strbuf_get_str(temp_buff), '1');
  if (last_one) {
    wmem_strbuf_truncate(temp_buff, (gsize) (last_one - wmem_strbuf_get_str(temp_buff)) + 1);
  }

  if (wmem_strbuf_get_len(temp_buff) > 0) {
    proto_tree_add_bytes_format_value(bitmap_tree, hf_rtps_bitmap, tvb,
            original_offset + 12, offset - original_offset - 12,
            NULL, "%s", wmem_strbuf_get_str(temp_buff));
  }

  proto_item_set_len(ti_tree, offset-original_offset);

  /* Add analysis of the information */
  if (num_bits > 0 && show_analysis) {
    proto_item_append_text(ti, "%s in range [%" PRIu64 ",%" PRIu64 "]",
        wmem_strbuf_get_str(analysis_buff), first_seq_number, first_seq_number + num_bits - 1);
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
static int rtps_util_add_fragment_number_set(proto_tree *tree, packet_info *pinfo, tvbuff_t *tvb,
                        gint offset, const guint encoding, const char *label, gint section_size) {
  guint64 base;
  gint32 num_bits;
  guint32 data;
  wmem_strbuf_t *temp_buff = wmem_strbuf_new_label(wmem_packet_scope());
  gchar *last_one;
  int i, j, idx;
  proto_item *ti;
  proto_tree *bitmap_tree;
  const gint original_offset = offset;
  guint32 datamask;
  gint expected_size;
  gint base_size;

  bitmap_tree = proto_tree_add_subtree(tree, tvb, original_offset, offset-original_offset, ett_rtps_bitmap, &ti, label);

  /* RTI DDS 4.2d was sending the FragmentNumber_t as a 64-bit long integer
   * instead of 32-bit long.
   * Attempt to decode this section as 32-bit, then check if the size of the
   * message match what is here. If not re-decode it as 64-bit.
   */
  num_bits = tvb_get_guint32(tvb, offset+4, encoding);
  expected_size = ((num_bits + 31) / 32) * 4 + 8;
  if (expected_size == section_size) {
    base = (guint64)tvb_get_guint32(tvb, offset, encoding);
    base_size = 4;
    offset += 8;
  } else {
    /* Attempt to use 64-bit for base */
    num_bits = tvb_get_guint32(tvb, offset+8, encoding);
    /* num_bits/8 must be aligned to the 4-byte word */
    expected_size = (((num_bits / 8) + 3) / 4) * 4 + 12;
    if (expected_size == section_size) {
      guint64 hi = (guint64)tvb_get_guint32(tvb, offset, encoding);
      guint64 lo = (guint64)tvb_get_guint32(tvb, offset+4, encoding);
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
    data = tvb_get_guint32(tvb, offset, encoding);
    offset += 4;
    for (j = 0; j < 32; ++j) {
      datamask = (1U << (31-j));
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

  if (base_size == 8) {
    proto_tree_add_uint64(bitmap_tree, hf_rtps_fragment_number_base64, tvb, original_offset, 8,
                    base);
  } else {
    proto_tree_add_item(bitmap_tree, hf_rtps_fragment_number_base, tvb, original_offset, base_size, encoding);
  }
  proto_tree_add_uint(bitmap_tree, hf_rtps_fragment_number_num_bits, tvb, original_offset + base_size, 4, num_bits);

  if (wmem_strbuf_get_len(temp_buff) > 0) {
    proto_tree_add_bytes_format_value(bitmap_tree, hf_rtps_bitmap, tvb, original_offset + base_size + 4, offset - original_offset - base_size - 4,
                                        NULL, "%s", wmem_strbuf_get_str(temp_buff));
  }

  proto_item_set_len(ti, offset-original_offset);
  return offset;
}

static void rtps_util_insert_type_mapping_in_registry(packet_info *pinfo, type_mapping *type_mapping_object) {
  if (type_mapping_object) {
    if ((type_mapping_object->fields_visited & TOPIC_INFO_ALL_SET) == TOPIC_INFO_ALL_SET &&
              type_mapping_object->guid.fields_present == GUID_HAS_ALL &&
              !wmem_map_lookup(registry, &(type_mapping_object->guid))) {
        if (((type_mapping_object->guid.entity_id & 0x02) == 0x02) || ((type_mapping_object->guid.entity_id & 0x04) == 0x04)){
          /* If it is an application defined writer matches 0x02. Matches 0x04 if it is an application defined reader */
          type_mapping_object->dcps_publication_frame_number = pinfo->num;
          wmem_map_insert(registry, &(type_mapping_object->guid), type_mapping_object);
        }
    }
  }
}

static void rtps_util_store_type_mapping(packet_info *pinfo _U_, tvbuff_t *tvb, gint offset,
        type_mapping * type_mapping_object, const gchar * value,
        gint topic_info_add_id) {
    if (enable_topic_info && type_mapping_object) {
      switch (topic_info_add_id) {
        case TOPIC_INFO_ADD_GUID: {
          type_mapping_object->guid.host_id = tvb_get_ntohl(tvb, offset);
          type_mapping_object->guid.app_id = tvb_get_ntohl(tvb, offset+4);
          type_mapping_object->guid.instance_id = tvb_get_ntohl(tvb, offset+8);
          type_mapping_object->guid.entity_id = tvb_get_ntohl(tvb, offset+12);
          type_mapping_object->guid.fields_present |=
                  GUID_HAS_HOST_ID|GUID_HAS_APP_ID|GUID_HAS_INSTANCE_ID|GUID_HAS_ENTITY_ID;
          type_mapping_object->fields_visited =
                  type_mapping_object->fields_visited | TOPIC_INFO_ADD_GUID;
          break;
        }
        case TOPIC_INFO_ADD_TOPIC_NAME: {
          (void) g_strlcpy(type_mapping_object->topic_name, value, MAX_TOPIC_AND_TYPE_LENGTH);
          type_mapping_object->fields_visited =
                  type_mapping_object->fields_visited | TOPIC_INFO_ADD_TOPIC_NAME;
          break;
        }
        case TOPIC_INFO_ADD_TYPE_NAME: {
          (void) g_strlcpy(type_mapping_object->type_name, value, MAX_TOPIC_AND_TYPE_LENGTH);
          type_mapping_object->fields_visited =
                  type_mapping_object->fields_visited | TOPIC_INFO_ADD_TYPE_NAME;
          break;
        }

        default:
          break;
      }
    }
}

static guint hash_by_guid(gconstpointer key) {
  const endpoint_guid * guid = (const endpoint_guid *) key;
  DISSECTOR_ASSERT(guid->fields_present & GUID_HAS_APP_ID);
  return g_int_hash(&(guid->app_id));
}

static gboolean compare_by_guid(gconstpointer guid_a, gconstpointer guid_b) {
  return memcmp(guid_a, guid_b, sizeof(endpoint_guid)) == 0;
}

static guint get_domain_id_from_tcp_discovered_participants(wmem_map_t *map, endpoint_guid* key) {
  participant_info *p_info = (participant_info*)wmem_map_lookup(map, (void*)key);
  return (p_info != NULL) ? p_info->domainId: RTPS_UNKNOWN_DOMAIN_ID_VAL;
}

static guint coherent_set_key_hash_by_key(gconstpointer key) {
  return wmem_strong_hash((const guint8 *)key, sizeof(coherent_set_key));
}

static gboolean compare_by_coherent_set_key(gconstpointer key_a, gconstpointer key_b) {
  return memcmp(key_a, key_b, sizeof(coherent_set_key)) == 0;
}

static type_mapping * rtps_util_get_topic_info(endpoint_guid * guid) {
  /* At this point, we know the boolean enable_topic_info is true */
  type_mapping * result = NULL;
  if (guid) {
    if (guid->fields_present == GUID_HAS_ALL)
      result = (type_mapping *)wmem_map_lookup(registry, guid);
  }
  return result;
}

static void rtps_util_format_typename(gchar * type_name, gchar ** output) {
   gchar ** tokens;
   gchar * result_caps;
   /* The standard specifies that the max size of a type name
      can be 255 bytes */
   tokens = wmem_strsplit(wmem_packet_scope(), type_name, "::", 255);
   result_caps = wmem_strjoinv(wmem_packet_scope(), "_", tokens);
   *output = wmem_ascii_strdown(wmem_packet_scope(), result_caps, -1);

}

static void rtps_util_topic_info_add_tree(proto_tree *tree, tvbuff_t *tvb,
  gint offset, endpoint_guid * guid) {
  if (enable_topic_info) {
    proto_tree * topic_info_tree;
    proto_item * ti;
    type_mapping * type_mapping_object = rtps_util_get_topic_info(guid);
    if (type_mapping_object != NULL) {
      topic_info_tree = proto_tree_add_subtree(tree, tvb, offset, 0,
                ett_rtps_topic_info, NULL, "[Topic Information (from Discovery)]");
      ti = proto_tree_add_string(topic_info_tree, hf_rtps_param_topic_name, tvb, offset, 0,
                type_mapping_object->topic_name);
      proto_item_set_generated(ti);
      ti = proto_tree_add_string(topic_info_tree, hf_rtps_param_type_name, tvb, offset, 0,
                type_mapping_object->type_name);
      proto_item_set_generated(ti);
      ti = proto_tree_add_uint(topic_info_tree, hf_rtps_dcps_publication_data_frame_number,
          tvb, 0, 0, type_mapping_object->dcps_publication_frame_number);
      proto_item_set_generated(ti);
    }
  }
}


/* Uncompress data and returns it uncompressed on a new tvb.
 *
 * @param[in] tree a chunk of data in the tvb and return a new tvb with the uncompressed data
 * @param[in] tvb
 * @param[in] offset offset at the begining of the compressed data.
 * @param[in] size in bytes from the initial offset to the end of the serialized data
 * @param[in] compressed_size size in bytes of the compressed chunk in the tvb.
 * @param[out] True if it tries to uncompress the data. In environment where Zlib is not available this will be false. This is used for
 *   distinguis when the data is not decompressed because Zlib is not available (not warning) and cases where it is but fails (warning).
 *
 * @return The uncompressed data on a new TVB if everything goes fine. Otherwise NULL
 */
static
tvbuff_t *rtps_util_get_uncompressed_tvb_zlib(
        tvbuff_t *tvb _U_,
        const gint offset _U_,
        const guint compressed_size _U_,
        gboolean *tried_to_decompress) {
    tvbuff_t *uncompressed_tvb = NULL;
#ifdef HAVE_ZLIB
    /* If ZLIB is available always try to decompress. */
    *tried_to_decompress = TRUE;
    uncompressed_tvb = tvb_new_subset_length_caplen(tvb, offset, compressed_size, -1);
    uncompressed_tvb = tvb_uncompress(uncompressed_tvb, 0, compressed_size);
#else
    *tried_to_decompress = FALSE;
#endif
    return uncompressed_tvb;
}

/*
 * 0...2...........8...............16
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * | X X X X X X X X X X X | C C C P P |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  X = Unused options bits
 *  C = Compression bits
 *  P = Padding bits
 *  C = 0b111 would be extended compression options which would come in as an
 *      additional header before the payload.
 *  C = 0b000 to indicate no compression
*/

/* Dissects the encapsultaion options
*
* @param[in] tree
* @param[in] packet info.
* @param[in] tvb
* @param[in] offset at the begining of the encapsulation options.
* @param[out] encapsulation_options_out If not null it will contain the encapsulation options
* @param[out] compression_option_out If not null it will contain the compression option
* @param[out] padding_bytes_out If not null it will contain the padding bytes
* @param[out] extended_header_bits_out If not null it will contain the extended header bits
* @return the offset after the encapsulation options
* @note All output parameters are optional.
*/
static
gint rtps_util_dissect_encapsulation_options(
        proto_tree *tree,
        tvbuff_t *tvb,
        gint offset,
        gint16 *encapsulation_options_out,
        guint8 *compression_options_out,
        guint8 *padding_bytes_out,
        guint8 *extended_header_bits_out) {
    guint8 compression_options = 0;
    proto_tree *compression_options_subtree = NULL;
    gint16 encapsulation_options = 0;
    guint8 padding_bytes = 0;
    guint8 extended_header_bits = 0;

    /* Encapsulation length (or option). Always big endian. */
    encapsulation_options = tvb_get_gint16(tvb, offset, ENC_BIG_ENDIAN);
    if (encapsulation_options != 0) {
        compression_options_subtree = proto_tree_add_subtree_format(
                tree,
                tvb,
                offset,
                2,
                ett_rtps_data_encapsulation_options,
                NULL,
                "Encapsulation options (0x%02x)",
                encapsulation_options);
        /* If compression options ENCAPSULATION_OPTIONS_COMPRESSION_EXTENDED_HEADER_VALUE bits are set, the
        header contains an extra field */
        extended_header_bits = (encapsulation_options
                & ENCAPSULATION_OPTIONS_COMPRESSION_EXTENDED_HEADER_VALUE);
        GET_ENCAPSULATION_COMPRESSION_OPTIONS(encapsulation_options, compression_options);
        padding_bytes = (encapsulation_options & ENCAPSULATION_OPTIONS_COMPRESSION_PADDING_BYTES_MASK);
        proto_tree_add_int(
                compression_options_subtree,
                hf_rtps_encapsulation_options_compression_plugin_class_id,
                tvb,
                offset + 1,
                1,
                compression_options);
        proto_tree_add_int(
                compression_options_subtree,
                hf_rtps_padding_bytes,
                tvb,
                offset + 1,
                1,
                padding_bytes);
        offset += 2;
        padding_bytes = encapsulation_options & ENCAPSULATION_OPTIONS_COMPRESSION_PADDING_BYTES_MASK;
    } else {
        /* Encapsulation length (or option). Always big endian. */
        proto_tree_add_item(
                tree,
                hf_rtps_param_serialize_encap_len,
                tvb,
                offset,
                2,
                ENC_BIG_ENDIAN);
        offset += 2;
    }
    /* Set the optional outputs */
    if (encapsulation_options_out != NULL) {
        *encapsulation_options_out = encapsulation_options;
    }
    if (compression_options_out != NULL) {
        *compression_options_out = compression_options;
    }
    if (padding_bytes_out != NULL) {
        *padding_bytes_out = padding_bytes;
    }
    if (extended_header_bits_out != NULL) {
        *extended_header_bits_out = extended_header_bits;
    }
    return offset;
}

static gboolean rtps_util_topic_info_add_column_info(
    packet_info *pinfo, endpoint_guid * guid,
    rtps_dissector_data * data) {
    gboolean added = FALSE;
    if (enable_topic_info) {
        type_mapping * type_mapping_object = rtps_util_get_topic_info(guid);

        /* This part shows information available for the sample */
        if (data && !(data->info_displayed) && (type_mapping_object != NULL)) {
            col_append_sep_str(pinfo->cinfo, COL_INFO, " -> ", type_mapping_object->topic_name);
            data->info_displayed = TRUE;
            added = TRUE;
        }
    }
    /* Return false so the content is dissected by the codepath following this one */
    return added;
}

static gboolean rtps_util_topic_info_add_column_info_and_try_dissector(proto_tree *tree,
        packet_info *pinfo, tvbuff_t *tvb, gint offset, endpoint_guid * guid,
        rtps_dissector_data * data, guint encoding, guint encoding_version, gboolean try_dissection_from_type_object) {
  if (enable_topic_info) {
    type_mapping * type_mapping_object = rtps_util_get_topic_info(guid);
    if (type_mapping_object != NULL) {
      gchar * dissector_name = NULL;
      tvbuff_t *next_tvb;

      rtps_util_topic_info_add_column_info(pinfo, guid, data);
      /* This part shows information available for the sample
      if (data && !(data->info_displayed)) {
        col_append_sep_str(pinfo->cinfo, COL_INFO, " -> ", type_mapping_object->topic_name);
        data->info_displayed = TRUE;
      }
      */

      if (try_dissection_from_type_object && enable_user_data_dissection) {
        dissection_info * info = (dissection_info *) wmem_map_lookup(dissection_infos, &(type_mapping_object->type_id));
        if (info != NULL) {
          proto_item_append_text(tree, " (TypeId: 0x%016" PRIx64 ")", info->type_id);
          return dissect_user_defined(tree, tvb, offset, encoding, encoding_version, info,
              info->type_id, info->member_name, EXTENSIBILITY_INVALID, offset,
              0 /* flags */, 0 /* member_id */, TRUE);
        }
      }
      /* This part tries to dissect the content using a dissector */
      next_tvb = tvb_new_subset_remaining(tvb, offset);

      rtps_util_format_typename(type_mapping_object->type_name, &dissector_name);
      return dissector_try_string(rtps_type_name_table, dissector_name,
              next_tvb, pinfo, tree, data);
      }
    }
  /* Return false so the content is dissected by the codepath following this one */
  return FALSE;
}

static gint rtps_util_add_rti_topic_query_service_request(proto_tree * tree,
        tvbuff_t * tvb, gint offset, guint encoding) {
    /*
    struct TopicQuerySelection {
        string filter_class_name; //@Optional 0
        string filter_expression; // 1
        sequence<string> filter_parameters;
    }; //@top-level false
    //@Extensibility MUTABLE_EXTENSIBILITY

    struct TopicQueryData {
        TopicQuerySelection topic_query_selection;
        SequenceNumber_t sync_sequence_number;
        string topic_name;
        GUID_t original_related_reader_guid;
    }; //@top-level false
    //@Extensibility MUTABLE_EXTENSIBILITY
    */
  proto_tree * topic_query_tree, * topic_query_selection_tree, *topic_query_filter_params_tree;
  proto_item * ti;
  guint16 encapsulation_id, encapsulation_opt;
  guint32 param_id, param_length, param_length_2, num_filter_params;
  gint alignment_zero, tmp_offset;
  guint32 i;
  topic_query_tree = proto_tree_add_subtree(tree, tvb, offset,
      0 /* To be defined */, ett_rtps_topic_query_tree, &ti, "Topic Query Data");

  /* Encapsulation Id */
  encapsulation_id =  tvb_get_ntohs(tvb, offset);   /* Always big endian */
  proto_tree_add_uint(topic_query_tree, hf_rtps_encapsulation_id,
        tvb, offset, 2, encapsulation_id);
  offset += 2;
  encoding = get_encapsulation_endianness(encapsulation_id);
  /* Encapsulation length (or option) */
  encapsulation_opt =  tvb_get_ntohs(tvb, offset);    /* Always big endian */
  proto_tree_add_uint(topic_query_tree, hf_rtps_encapsulation_options, tvb,
        offset, 2, encapsulation_opt);
  offset += 2;
  alignment_zero = offset;
  rtps_util_dissect_parameter_header(tvb, &offset, encoding, &param_id, &param_length);
  tmp_offset = offset;
  {
    /* TopicQuerySelection */
    topic_query_selection_tree = proto_tree_add_subtree(topic_query_tree, tvb, tmp_offset,
            0 /* To be defined */, ett_rtps_topic_query_selection_tree, &ti, "Topic Query Selection");

    SHORT_ALIGN_ZERO(tmp_offset,alignment_zero);
    rtps_util_dissect_parameter_header(tvb, &tmp_offset, encoding, &param_id, &param_length_2);
    if (param_id == 0) { /* Optional string filter_class_name */
      LONG_ALIGN_ZERO(tmp_offset, alignment_zero);
      rtps_util_add_string(topic_query_selection_tree, tvb, tmp_offset,
                           hf_rtps_topic_query_selection_filter_class_name, encoding);
    }
    tmp_offset += param_length_2;

    SHORT_ALIGN_ZERO(tmp_offset,alignment_zero);
    rtps_util_dissect_parameter_header(tvb, &tmp_offset, encoding, &param_id, &param_length_2);

    LONG_ALIGN_ZERO(tmp_offset, alignment_zero);
    tmp_offset = rtps_util_add_string(topic_query_selection_tree, tvb, tmp_offset,
            hf_rtps_topic_query_selection_filter_expression, encoding);

    SHORT_ALIGN_ZERO(tmp_offset,alignment_zero);
    rtps_util_dissect_parameter_header(tvb, &tmp_offset, encoding, &param_id, &param_length_2);

    num_filter_params = tvb_get_guint32(tvb, tmp_offset, encoding);
    proto_tree_add_item(topic_query_selection_tree, hf_rtps_topic_query_selection_num_parameters,
                tvb, tmp_offset, 4, encoding);
    topic_query_filter_params_tree = proto_tree_add_subtree_format(topic_query_selection_tree, tvb,
                tmp_offset + 4, 0 /* To be defined */, ett_rtps_topic_query_filter_params_tree, &ti,
                "Filter Parameters (size = %u)", num_filter_params);
    tmp_offset += 4;
    for (i = 0; i < num_filter_params; ++i) {
      guint32 string_size;
      gchar * retVal;
      LONG_ALIGN_ZERO(tmp_offset, alignment_zero);
      string_size = tvb_get_guint32(tvb, tmp_offset, encoding);
      retVal = tvb_get_string_enc(wmem_packet_scope(), tvb, tmp_offset+4, string_size, ENC_ASCII);

      proto_tree_add_string_format(topic_query_filter_params_tree,
            hf_rtps_topic_query_selection_filter_parameter, tvb,
            tmp_offset, string_size+4, retVal, "%s[%d]: %s", "Filter Parameter", i, retVal);

      tmp_offset += (4 + string_size);
    }
  }
  offset += param_length;
  SHORT_ALIGN_ZERO(offset,alignment_zero);
  rtps_util_dissect_parameter_header(tvb, &offset, encoding, &param_id, &param_length);

  rtps_util_add_seq_number(topic_query_tree, tvb, offset, encoding, "Sync Sequence Number");
  offset += param_length;

  SHORT_ALIGN_ZERO(offset,alignment_zero);
  rtps_util_dissect_parameter_header(tvb, &offset, encoding, &param_id, &param_length);

  LONG_ALIGN_ZERO(offset, alignment_zero);
  rtps_util_add_string(topic_query_tree, tvb, offset,
            hf_rtps_topic_query_topic_name, encoding);
  offset += param_length;

  SHORT_ALIGN_ZERO(offset,alignment_zero);
  rtps_util_dissect_parameter_header(tvb, &offset, encoding, &param_id, &param_length);

  rtps_util_add_generic_guid_v2(topic_query_tree, tvb, offset,
          hf_rtps_topic_query_original_related_reader_guid,
          hf_rtps_param_host_id, hf_rtps_param_app_id, hf_rtps_param_instance_id,
          hf_rtps_param_entity, hf_rtps_param_entity_key, hf_rtps_param_hf_entity_kind,
          NULL);

  offset += param_length;

  return offset;
}

static gint rtps_util_add_rti_locator_reachability_service_request(proto_tree * tree,
        packet_info *pinfo, tvbuff_t * tvb, gint offset, guint encoding) {
  proto_tree * locator_reachability_tree, * locator_seq_tree;
  proto_item * ti;
  guint16 encapsulation_id, encapsulation_opt;
  guint32 param_id, param_length, seq_length, i;
  locator_reachability_tree = proto_tree_add_subtree(tree, tvb, offset,
        0 /* To be defined */, ett_rtps_locator_reachability_tree, &ti, "Locator Reachability Data");
  /* Encapsulation Id */
  encapsulation_id =  tvb_get_ntohs(tvb, offset);   /* Always big endian */
  proto_tree_add_uint(locator_reachability_tree, hf_rtps_encapsulation_id,
        tvb, offset, 2, encapsulation_id);
  offset += 2;
  encoding = get_encapsulation_endianness(encapsulation_id);
  /* Encapsulation length (or option) */
  encapsulation_opt =  tvb_get_ntohs(tvb, offset);    /* Always big endian */
  proto_tree_add_uint(locator_reachability_tree, hf_rtps_encapsulation_options, tvb,
        offset, 2, encapsulation_opt);
  offset += 2;

  rtps_util_dissect_parameter_header(tvb, &offset, encoding, &param_id, &param_length);

  seq_length = tvb_get_guint32(tvb, offset, encoding);
  locator_seq_tree = proto_tree_add_subtree_format(locator_reachability_tree, tvb, offset,
            param_length, ett_rtps_locator_list_tree, &ti, "Locator List [Size = %u]", seq_length);
  offset += 4;
  for(i = 0; i < seq_length; i++) {
    rtps_util_add_locator_t(locator_seq_tree, pinfo, tvb, offset, encoding, "Locator");
    offset += 24;
  }
  return offset;
}

static gint rtps_util_add_rti_service_request(proto_tree * tree, packet_info *pinfo, tvbuff_t * tvb,
        gint offset, const guint encoding, guint32 service_id) {
  switch (service_id) {
    case RTI_SERVICE_REQUEST_ID_TOPIC_QUERY:
      offset = rtps_util_add_rti_topic_query_service_request(tree, tvb, offset + 4,
                  encoding);
      break;
    case RTI_SERVICE_REQUEST_ID_LOCATOR_REACHABILITY:
      offset = rtps_util_add_rti_locator_reachability_service_request(tree, pinfo, tvb, offset + 4,
                  encoding);
      break;
    case RTI_SERVICE_REQUEST_ID_UNKNOWN: {
      guint32 seq_length;
      seq_length = tvb_get_guint32(tvb, offset, encoding);
      proto_tree_add_item(tree, hf_rtps_srm_request_body,
                    tvb, offset + 4, seq_length, ENC_NA);
      offset += (seq_length + 4);
      break;
    }
  }
  return offset;
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
          expert_add_info_format(pinfo, param_len_item, &ei_rtps_parameter_value_invalid, "ERROR: parameter value too small (must be at least %d octets)", size); \
          break;                                                                     \
        }

static gboolean dissect_parameter_sequence_rti_dds(proto_tree *rtps_parameter_tree, packet_info *pinfo, tvbuff_t *tvb,
  proto_item *parameter_item, proto_item * param_len_item, gint offset,
  const guint encoding, int param_length, guint16 parameter, type_mapping * type_mapping_object,
  gboolean is_inline_qos, guint vendor_id) {

  switch(parameter) {

  case PID_DATA_TAGS:
      ENSURE_LENGTH(4);
      rtps_util_add_data_tags(rtps_parameter_tree, tvb, offset, encoding, param_length);
      break;

  case PID_SAMPLE_SIGNATURE:
      ENSURE_LENGTH(16);
      proto_tree_add_item(rtps_parameter_tree, hf_rtps_param_sample_signature_epoch, tvb,
                  offset, 8, encoding);
      proto_tree_add_item(rtps_parameter_tree, hf_rtps_param_sample_signature_nonce, tvb,
                  offset+8, 4, encoding);
      proto_tree_add_item(rtps_parameter_tree, hf_rtps_param_sample_signature_length, tvb,
                  offset+12, 4, encoding);
      proto_tree_add_item(rtps_parameter_tree, hf_rtps_param_sample_signature_signature, tvb,
                  offset+16, param_length-16, ENC_NA);
      break;

    case PID_ENABLE_AUTHENTICATION:
      ENSURE_LENGTH(4);
      proto_tree_add_item(rtps_parameter_tree, hf_rtps_param_enable_authentication, tvb,
            offset, 4, ENC_NA);
      break;

    case PID_BUILTIN_ENDPOINT_QOS:
      ENSURE_LENGTH(1);
      proto_tree_add_item(rtps_parameter_tree, hf_rtps_param_builtin_endpoint_qos, tvb,
              offset, 1, ENC_NA);
      break;

    case PID_ENDPOINT_SECURITY_INFO: {
      guint32 flags;
      ENSURE_LENGTH(8);
      flags = tvb_get_guint32(tvb, offset, encoding);
      proto_tree_add_bitmask_value(rtps_parameter_tree, tvb, offset,
              hf_rtps_param_endpoint_security_attributes_mask, ett_rtps_flags,
              ENDPOINT_SECURITY_INFO_FLAGS, flags);
      flags = tvb_get_guint32(tvb, offset, encoding);
      proto_tree_add_bitmask_value(rtps_parameter_tree, tvb, offset,
              hf_rtps_param_plugin_endpoint_security_attributes_mask, ett_rtps_flags,
              PLUGIN_ENDPOINT_SECURITY_INFO_FLAGS, flags);
      break;
    }

    case PID_PARTICIPANT_SECURITY_INFO: {
      guint32 flags;
      ENSURE_LENGTH(8);
      flags = tvb_get_guint32(tvb, offset, encoding);
      proto_tree_add_bitmask_value(rtps_parameter_tree, tvb, offset,
              hf_rtps_param_participant_security_attributes_mask, ett_rtps_flags,
              PARTICIPANT_SECURITY_INFO_FLAGS, flags);
      flags = tvb_get_guint32(tvb, offset, encoding);
      proto_tree_add_bitmask_value(rtps_parameter_tree, tvb, offset,
              hf_rtps_param_plugin_participant_security_attributes_mask, ett_rtps_flags,
              PLUGIN_PARTICIPANT_SECURITY_INFO_FLAGS, flags);
      break;
    }

    case PID_VENDOR_BUILTIN_ENDPOINT_SET: {
      guint32 flags;
      ENSURE_LENGTH(4);
      flags = tvb_get_guint32(tvb, offset, encoding);
      proto_tree_add_bitmask_value(rtps_parameter_tree, tvb, offset,
                hf_rtps_param_vendor_builtin_endpoint_set_flags, ett_rtps_flags,
                VENDOR_BUILTIN_ENDPOINT_FLAGS, flags);
      break;
    }
  /* 0...2...........7...............15.............23...............31
   * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   * |    Unsigned long classId                                      |
   * +---------------+---------------+---------------+---------------+
   * |    Unsigned long uncompressedSerializedLength                 |
   * +---------------+---------------+---------------+---------------+
   * |    byteSeq compressedSerializedTypeObject                     |
   * +---------------+---------------+---------------+---------------+
   * classId:
   *  value(0) RTI_OSAPI_COMPRESSION_CLASS_ID_NONE
   *  value(1) RTI_OSAPI_COMPRESSION_CLASS_ID_ZLIB
   *  value(2) RTI_OSAPI_COMPRESSION_CLASS_ID_BZIP2
   *  value(-1) RTI_OSAPI_COMPRESSION_CLASS_ID_AUTO
   */
    case PID_TYPE_OBJECT_LB: {
      guint compressed_size;
      guint decompressed_size;
      guint compression_plugin_class;
      tvbuff_t *compressed_type_object_subset;

      ENSURE_LENGTH(8);
      proto_tree_add_item(rtps_parameter_tree, hf_rtps_compression_plugin_class_id, tvb, offset, 4, encoding);
      proto_tree_add_item(rtps_parameter_tree, hf_rtps_uncompressed_serialized_length, tvb, offset + 4, 4, encoding);

      compression_plugin_class = tvb_get_guint32(tvb, offset, encoding);
      decompressed_size = tvb_get_guint32(tvb, offset + 4, encoding);
      /* Get the numer of bytes (elements) in the sequence */
      compressed_size = tvb_get_guint32(tvb, offset + 8, encoding);

      switch(compression_plugin_class)  {
        case RTI_OSAPI_COMPRESSION_CLASS_ID_ZLIB: {
          /* + 12 Because First 4 bytes of the sequence are the number of elements in the sequence */
          proto_tree_add_item(rtps_parameter_tree, hf_rtps_compressed_serialized_type_object, tvb, offset + 12, param_length - 8, encoding);
          compressed_type_object_subset = tvb_new_subset_length(tvb, offset + 12, decompressed_size);
          rtps_add_zlib_compressed_typeobject(rtps_parameter_tree, pinfo, compressed_type_object_subset,
            0, encoding, compressed_size, decompressed_size, type_mapping_object);
          break;
        }
        case RTI_OSAPI_COMPRESSION_CLASS_ID_NONE: {
          compressed_type_object_subset = tvb_new_subset_length(tvb, offset + 12, decompressed_size);
          rtps_util_add_typeobject(rtps_parameter_tree, pinfo,
            compressed_type_object_subset, 0, encoding, decompressed_size, type_mapping_object);
          break;
        }
        default: {
          /* + 12 Because First 4 bytes of the sequence are the number of elements in the sequence */
          proto_tree_add_item(rtps_parameter_tree, hf_rtps_compressed_serialized_type_object, tvb, offset + 12, param_length - 8, encoding);
        }
      }
      break;
    }

    case PID_ENDPOINT_SECURITY_ATTRIBUTES: {
      guint32 flags;
      ENSURE_LENGTH(4);
      flags = tvb_get_guint32(tvb, offset, encoding);
      proto_tree_add_bitmask_value(rtps_parameter_tree, tvb, offset,
        hf_rtps_param_endpoint_security_attributes, ett_rtps_flags,
      ENDPOINT_SECURITY_ATTRIBUTES, flags);
      break;
    }

    case PID_TOPIC_QUERY_PUBLICATION: {
      ENSURE_LENGTH(8);
      proto_tree_add_item(rtps_parameter_tree, hf_rtps_param_topic_query_publication_enable,
                      tvb, offset, 1, encoding);
      proto_tree_add_item(rtps_parameter_tree, hf_rtps_param_topic_query_publication_sessions,
                      tvb, offset+4, 4, encoding);
      break;
    }

    case PID_ENDPOINT_PROPERTY_CHANGE_EPOCH: {
      ENSURE_LENGTH(8);
      proto_tree_add_item(rtps_parameter_tree, hf_rtps_param_endpoint_property_change_epoch,
              tvb, offset, 8, encoding);
      break;
    }

    case PID_TOPIC_QUERY_GUID:
      if (is_inline_qos) {
        ENSURE_LENGTH(16);
        rtps_util_add_generic_guid_v2(rtps_parameter_tree, tvb, offset,
                      hf_rtps_endpoint_guid, hf_rtps_param_host_id, hf_rtps_param_app_id,
                      hf_rtps_param_instance_id, hf_rtps_param_entity, hf_rtps_param_entity_key,
                      hf_rtps_param_hf_entity_kind, NULL);
      }
      break;

    case PID_REACHABILITY_LEASE_DURATION:
      ENSURE_LENGTH(8);
      rtps_util_add_timestamp_sec_and_fraction(rtps_parameter_tree, tvb, offset, encoding,
                           hf_rtps_participant_lease_duration);
    break;

    case PID_RELATED_SOURCE_GUID: {
      ENSURE_LENGTH(16);
      /* PID_RELATED_SOURCE_GUID */
      rtps_util_add_generic_guid_v2(rtps_parameter_tree, tvb, offset,
                  hf_rtps_endpoint_guid, hf_rtps_param_host_id, hf_rtps_param_app_id,
                  hf_rtps_param_instance_id, hf_rtps_param_entity, hf_rtps_param_entity_key,
                  hf_rtps_param_hf_entity_kind, NULL);
      break;
    }
    /* 0...2...........7...............15.............23...............31
    * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    * | PID_TRANSPORT_INFO_LIST       |            length             |
    * +---------------+---------------+---------------+---------------+
    * |    unsigned long     Seq.Length                               |
    * +---------------+---------------+---------------+---------------+
    * |                              ...                              |
    * |                      TransportInfo 1                          |
    * |                              ...                              |
    * +---------------+---------------+---------------+---------------+
    * |                              ...                              |
    * |                      TransportInfo 2                          |
    * |                              ...                              |
    * +---------------+---------------+---------------+---------------+
    * |                              ...                              |
    * |                      TransportInfo n                          |
    * |                              ...                              |
    * +---------------+---------------+---------------+---------------+
    *
    * IDL:
    *    struct TRANSPORT_INFO {
    *        long classid;
    *        long messageSizeMax;
    *    };
    *
    *    struct TRANSPORT_INFO_LIST {
    *        Sequence<TRANSPORT_INFO> TransportInfoList;
    *    };
    *
    */
    /* PID_RELATED_READER_GUID and PID_TRANSPORT_INFO_LIST have the same value */
    case PID_TRANSPORT_INFO_LIST: {
      if (is_inline_qos) {
        ENSURE_LENGTH(16);
        /* PID_RELATED_READER_GUID */
        rtps_util_add_generic_guid_v2(rtps_parameter_tree, tvb, offset,
                      hf_rtps_endpoint_guid, hf_rtps_param_host_id, hf_rtps_param_app_id,
                      hf_rtps_param_instance_id, hf_rtps_param_entity, hf_rtps_param_entity_key,
                      hf_rtps_param_hf_entity_kind, NULL);
      } else {
        ENSURE_LENGTH(4);
        {
          int i;
          guint32 temp_offset;
          guint32 seq_size = tvb_get_guint32(tvb, offset, encoding);
          if (seq_size > 0) {
            temp_offset = offset+4; /* move to first transportInfo */
            i = 1;
            while(seq_size-- > 0) {
              rtps_util_add_transport_info(rtps_parameter_tree, tvb, temp_offset, encoding, i);
              temp_offset += 8;
              ++i;
            }
          }
        }
      }
      break;
    }

    /* PID_DIRECT_COMMUNICATION and PID_SOURCE_GUID have the same value */
    case PID_DIRECT_COMMUNICATION: {
      if (is_inline_qos) {
        ENSURE_LENGTH(16);
        /* PID_SOURCE_GUID */
        rtps_util_add_generic_guid_v2(rtps_parameter_tree, tvb, offset,
          hf_rtps_endpoint_guid, hf_rtps_param_host_id, hf_rtps_param_app_id,
          hf_rtps_param_instance_id, hf_rtps_param_entity, hf_rtps_param_entity_key,
          hf_rtps_param_hf_entity_kind, NULL);
      } else {
        proto_tree_add_item(rtps_parameter_tree, hf_rtps_direct_communication, tvb, offset, 1, ENC_NA );
      }
      break;
    }

    /* Product Version Version 5.3.1 and earlier
    * 0...2...........7...............15.............23...............31
    * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    * | PID_TYPE_CONSISTENCY_KIND     |            length             |
    * +---------------+---------------+---------------+---------------+
    * | unsigned short value Kind     | = =  u n u s e d  = = = = = = |
    * +---------------+---------------+---------------+---------------+
    *
    * Product Version 5.3.3 and later
    * 0...2...........7...............15.............23...............31
    * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    * | PID_TYPE_CONSISTENCY_KIND     |            length             |
    * +---------------+---------------+---------------+---------------+
    * | unsigned short value Kind     | Boolean ISeqB | Boolean IStrB |
    * +---------------+---------------+---------------+---------------+
    * | Boolean IMemN | Boolean PTypW | Boolean FtypV | Boolean IEnLN |
    * +---------------+---------------+---------------+---------------+
    * ISeqB = Ignore Sequence Names
    * IStrB = Ignore String names
    * IMemN = Ignore Member Names
    * PTypW = Prevent Type Widening
    * FtypV = Force Type Validation
    * IEnLN = Ignore Enum Literal Names
    */
    case PID_TYPE_CONSISTENCY: {
      if (param_length !=4 && param_length !=8) {
        expert_add_info_format(pinfo, rtps_parameter_tree,
          &pid_type_csonsistency_invalid_size,
          "PID_TYPE_CONSISTENCY invalid size. It has a size of %d bytes. Expected %d or %d bytes.",
          param_length, 4, 8);
        break;
      }
      proto_tree_add_item(rtps_parameter_tree, hf_rtps_param_type_consistency_kind, tvb, offset, 2, encoding);
      /* Parameter size can be used as a discriminator between product versions. */
      if (param_length == 8) {
          offset += 2;
          proto_tree_add_item(rtps_parameter_tree, hf_rtps_param_ignore_sequence_bounds,
            tvb, offset, 1, encoding);
          proto_tree_add_item(rtps_parameter_tree, hf_rtps_param_ignore_string_bounds,
            tvb, offset + 1, 1, encoding);
          proto_tree_add_item(rtps_parameter_tree, hf_rtps_param_ignore_member_names,
            tvb, offset + 2, 1, encoding);
          proto_tree_add_item(rtps_parameter_tree, hf_rtps_param_prevent_type_widening,
            tvb, offset + 3, 1, encoding);
          proto_tree_add_item(rtps_parameter_tree, hf_rtps_param_force_type_validation,
            tvb, offset + 4, 1, encoding);
          proto_tree_add_item(rtps_parameter_tree, hf_rtps_param_ignore_enum_literal_names,
            tvb, offset + 5, 1, encoding);
      }
      break;
    }

    /* ==================================================================
    * Here are all the deprecated items.
    */

    /* 0...2...........7...............15.............23...............31
    * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    * | PID_PRODUCT_VERSION           |            length             |
    * +---------------+---------------+---------------+---------------+
    * | uint8 major   | uint8 minor   | uint8 release |uint8 revision |
    * +---------------+---------------+---------------+---------------+
    */
    case PID_PRODUCT_VERSION: {
      ENSURE_LENGTH(4);
      rtps_util_add_product_version(rtps_parameter_tree, tvb, offset, vendor_id);
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
      ENSURE_LENGTH(4);
      proto_tree_add_item(rtps_parameter_tree, hf_rtps_param_plugin_promiscuity_kind, tvb, offset, 4, encoding);
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

    case PID_ENTITY_VIRTUAL_GUID: {
      ENSURE_LENGTH(16);
      rtps_util_add_guid_prefix_v2(rtps_parameter_tree, tvb, offset,
        hf_rtps_sm_guid_prefix, hf_rtps_sm_host_id, hf_rtps_sm_app_id,
        hf_rtps_sm_instance_id, 0);
      rtps_util_add_entity_id(rtps_parameter_tree, tvb, offset+12,
        hf_rtps_sm_entity_id, hf_rtps_sm_entity_id_key, hf_rtps_sm_entity_id_kind,
        ett_rtps_entity, "virtualGUIDSuffix", NULL);
      break;
    }


    /* 0...2...........7...............15.............23...............31
    * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    * | PID_SERVICE_KIND              |            length             |
    * +---------------+---------------+---------------+---------------+
    * | long    value                                                 |
    * +---------------+---------------+---------------+---------------+
    */
    case PID_SERVICE_KIND: {
      ENSURE_LENGTH(4);
      proto_tree_add_item(rtps_parameter_tree, hf_rtps_param_service_kind, tvb, offset, 4, encoding);
      break;
    }


    case PID_ROLE_NAME: {
      rtps_util_add_string(rtps_parameter_tree, tvb, offset, hf_rtps_param_role_name, encoding);
      break;
    }


    case PID_ACK_KIND: {
      ENSURE_LENGTH(4);
      proto_tree_add_item(rtps_parameter_tree, hf_rtps_param_acknowledgment_kind, tvb, offset, 4, encoding);
      break;
    }

    /* 0...2...........7...............15.............23...............31
    * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    * | PID_PEER_HOST_EPOCH           |            length             |
    * +---------------+---------------+---------------+---------------+
    * | unsigned long   epoch                                         |
    * +---------------+---------------+---------------+---------------+
    */
    case PID_PEER_HOST_EPOCH: {
      ENSURE_LENGTH(4);
      proto_tree_add_item(rtps_parameter_tree, hf_rtps_param_peer_host_epoch, tvb, offset, 4, encoding);
      break;
    }

    /* 0...2...........7...............15.............23...............31
    * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    * | PID_DOMAIN_ID|PID_RTI_DOMAIN_ID|           length             |
    * +---------------+---------------+---------------+---------------+
    * | long   domain_id                                              |
    * +---------------+---------------+---------------+---------------+
    */

    case PID_RTI_DOMAIN_ID:
    case PID_DOMAIN_ID: {
      if (is_inline_qos) { /* PID_RELATED_ORIGINAL_WRITER_INFO */
        ENSURE_LENGTH(16);
        rtps_util_add_guid_prefix_v2(rtps_parameter_tree, tvb, offset, hf_rtps_sm_guid_prefix,
                    hf_rtps_sm_host_id, hf_rtps_sm_app_id, hf_rtps_sm_instance_id, 0);
        rtps_util_add_entity_id(rtps_parameter_tree, tvb, offset+12, hf_rtps_sm_entity_id,
                    hf_rtps_sm_entity_id_key, hf_rtps_sm_entity_id_kind, ett_rtps_entity,
                    "virtualGUIDSuffix", NULL);
        /* Sequence number */
        rtps_util_add_seq_number(rtps_parameter_tree, tvb, offset+16,
                            encoding, "virtualSeqNumber");
      } else {
        ENSURE_LENGTH(4);
        proto_tree_add_item(rtps_parameter_tree, hf_rtps_domain_id, tvb, offset, 4, encoding);
        /* If using TCP we need to store the information of the domainId for that participant guid */
        if (pinfo->ptype == PT_TCP) {
          /* Each packet stores its participant guid in the private table. This is done in dissect_rtps */
          endpoint_guid *participant_guid = (endpoint_guid*)p_get_proto_data(pinfo->pool, pinfo, proto_rtps, RTPS_TCPMAP_DOMAIN_ID_PROTODATA_KEY);
          if (participant_guid != NULL) {
            /* Since this information is fixed there is no need to update in a second pass */
            if (!wmem_map_contains(discovered_tcp_participants, participant_guid)) {
              gint domainId = tvb_get_gint32(tvb, offset, encoding);
              participant_info *p_info = (participant_info*)wmem_new(wmem_file_scope(), participant_info);
              p_info->domainId = domainId;
              endpoint_guid *participant_guid_copy = (endpoint_guid*)wmem_memdup(wmem_file_scope(),
                participant_guid, sizeof(endpoint_guid));
              wmem_map_insert(discovered_tcp_participants,
                (const void*)participant_guid_copy, (void*)p_info);
            }
          }
        }
      }
      break;
    }

     /* 0...2...........7...............15.............23...............31
     * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     * | PID_DOMAIN_TAG                |            length             |
     * +---------------+---------------+---------------+---------------+
     * | long domain_tag.Length                                        |
     * +---------------+---------------+---------------+---------------+
     * | string domain_tag                                             |
     * | ...                                                           |
     * +---------------+---------------+---------------+---------------+
     */
    case PID_DOMAIN_TAG: {
       ENSURE_LENGTH(4);
       rtps_util_add_string(rtps_parameter_tree, tvb, offset, hf_rtps_domain_tag, encoding);
       break;
    }

    case PID_EXTENDED: {
      ENSURE_LENGTH(8);
      proto_tree_add_item(rtps_parameter_tree, hf_rtps_param_extended_parameter, tvb, offset, 4, encoding);
      offset += 4;
      proto_tree_add_item(rtps_parameter_tree, hf_rtps_param_extended_pid_length, tvb, offset, 4, encoding);
      break;
    }

    case PID_TYPE_OBJECT: {
      rtps_util_add_typeobject(rtps_parameter_tree, pinfo, tvb,
              offset, encoding, param_length, type_mapping_object);
      break;
    }

    /* 0...2...........7...............15.............23...............31
    * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    * | PID_TYPECODE_RTPS2            |            length             |
    * +---------------+---------------+---------------+---------------+
    * |                                                               |
    * +                    Type code description                      +
    * |                                                               |
    * +---------------+---------------+---------------+---------------+
    */
    case PID_TYPECODE:
    case PID_TYPECODE_RTPS2: {
      rtps_util_add_typecode(rtps_parameter_tree,
        tvb,
        offset,
        encoding,
        0,      /* indent level */
        0,      /* isPointer */
        -1,     /* bitfield */
        0,      /* isKey */
        offset,
        NULL,   /* name */
        -1,      /* not a seq field */
        NULL,   /* not an array */
        0);     /* ndds 4.0 hack: init to false */
      break;
    }

    /* 0...2...........7...............15.............23...............31
    * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    * | PID_DISABLE_POSITIVE_ACKS     |            length             |
    * +---------------+---------------+---------------+---------------+
    * | boolean value | = = = = = = = =  u n u s e d  = = = = = = = = |
    * +---------------+---------------+---------------+---------------+
    */
    case PID_DISABLE_POSITIVE_ACKS: {
      ENSURE_LENGTH(1);
      proto_tree_add_item(rtps_parameter_tree, hf_rtps_disable_positive_ack, tvb, offset, 1, ENC_NA );
      break;
    }

    /* 0...2...........7...............15.............23...............31
    * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    * | PID_EXPECTS_VIRTUAL_HB     |            length                |
    * +---------------+---------------+---------------+---------------+
    * | boolean value | = = = = = = = =  u n u s e d  = = = = = = = = |
    * +---------------+---------------+---------------+---------------+
    */
    case PID_EXPECTS_VIRTUAL_HB: {
      ENSURE_LENGTH(1);
      proto_tree_add_item(rtps_parameter_tree, hf_rtps_expects_virtual_heartbeat, tvb, offset, 1, ENC_NA );
      break;
    }

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
      gint32 number_of_channels, ch;
      proto_tree *channel_tree;
      proto_item *ti_channel;
      char temp_buff[20];
      gint old_offset;
      guint32 off = offset;

      ENSURE_LENGTH(4);
      proto_tree_add_item_ret_int(rtps_parameter_tree, hf_rtps_locator_filter_list_num_channels, tvb, off, 4, encoding, &number_of_channels );
      proto_item_append_text(parameter_item, " (%d channels)", number_of_channels );
      off += 4;

      if (number_of_channels == 0) {
        /* Do not dissect the rest */
        break;
      }

      /* filter name */
      off = rtps_util_add_string(rtps_parameter_tree, tvb, off, hf_rtps_locator_filter_list_filter_name, encoding);

      /* Foreach channel... */
      for (ch = 0; ch < number_of_channels; ++ch) {
        snprintf(temp_buff, 20, "Channel[%u]", ch);
        old_offset = off;
        channel_tree = proto_tree_add_subtree_format(rtps_parameter_tree, tvb, off, 0, ett_rtps_locator_filter_channel, &ti_channel, "Channel[%u]", ch);

        off = rtps_util_add_multichannel_locator_list(channel_tree, pinfo, tvb, off, temp_buff, encoding);
        /* Filter expression */
        off = rtps_util_add_string(rtps_parameter_tree, tvb, off, hf_rtps_locator_filter_list_filter_exp, encoding);

        /* Now we know the length of the channel data, set the length */
        proto_item_set_len(ti_channel, (off - old_offset));
      } /* End of for each channel */
      break;
    }/* End of case PID_LOCATOR_FILTER_LIST */

    /* 0...2...........7...............15.............23...............31
     * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     * | PID_UNICAST_LOCATOR_EX        |            0x8007             |
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
     * |                   Locator Sequence Length                     |
     * +---------------+---------------+---------------+---------------+
     * |           Locator 1           |             Locator 2         |
     * +---------------+---------------+---------------+---------------+
     */
    case PID_UNICAST_LOCATOR_EX: {
      ENSURE_LENGTH(28);
      rtps_util_add_locator_ex_t(rtps_parameter_tree, pinfo, tvb, offset, encoding, param_length);
      break;
    }

    case PID_ENDPOINT_SECURITY_SYMMETRIC_CIPHER_ALGO: {
        ENSURE_LENGTH(4);
        proto_tree_add_item(
            rtps_parameter_tree,
            hf_rtps_param_endpoint_security_symmetric_cipher_algorithms_used_bit,
            tvb,
            offset,
            4,
            encoding);
      break;
    }

    case PID_PARTICIPANT_SECURITY_SYMMETRIC_CIPHER_ALGO: {
        ENSURE_LENGTH(12);
        proto_tree_add_bitmask(
            rtps_parameter_tree,
            tvb,
            offset,
            hf_rtps_param_participant_security_symmetric_cipher_algorithms_supported_mask,
            ett_rtps_flags,
            SECURITY_SIMMETRIC_CIPHER_MASK_FLAGS,
            encoding);
        offset += 4;
        proto_tree_add_item(
            rtps_parameter_tree,
            hf_rtps_param_participant_security_symmetric_cipher_algorithms_builtin_endpoints_used_bit,
            tvb,
            offset,
            4,
            encoding);
        offset += 4;
        proto_tree_add_item(
            rtps_parameter_tree,
            hf_rtps_param_participant_security_symmetric_cipher_algorithms_builtin_endpoints_key_exchange_used_bit,
            tvb,
            offset,
            4,
            encoding);
      break;
    }

    case PID_PARTICIPANT_SECURITY_KEY_ESTABLISHMENT_ALGO: {
        ENSURE_LENGTH(8);
        proto_tree_add_bitmask(
            rtps_parameter_tree,
            tvb,
            offset,
            hf_rtps_param_participant_security_key_establishment_algorithms_supported_mask,
            ett_rtps_flags, SECURITY_KEY_ESTABLISHMENT_MASK_FLAGS,
            encoding);
        offset += 4;
        proto_tree_add_item(
            rtps_parameter_tree,
            hf_rtps_param_participant_security_key_establishment_algorithms_preferred_bit,
            tvb, offset,
            4,
            encoding);
      break;
    }

    case PID_PARTICIPANT_SECURITY_DIGITAL_SIGNATURE_ALGO: {
        ENSURE_LENGTH(16);
        proto_tree_add_bitmask(
            rtps_parameter_tree,
            tvb,
            offset,
            hf_rtps_param_participant_security_digital_signature_algorithms_trust_chain_supported_mask,
            ett_rtps_flags, SECURITY_DIGITAL_SIGNATURE_MASK_FLAGS,
            encoding);
        offset += 4;
        proto_tree_add_bitmask(
            rtps_parameter_tree,
            tvb,
            offset,
            hf_rtps_param_participant_security_digital_signature_algorithms_trust_chain_used_mask,
            ett_rtps_flags, SECURITY_DIGITAL_SIGNATURE_MASK_FLAGS,
            encoding);
        offset += 4;
        proto_tree_add_bitmask(
            rtps_parameter_tree,
            tvb,
            offset,
            hf_rtps_param_participant_security_digital_signature_algorithms_auth_supported_mask,
            ett_rtps_flags, SECURITY_DIGITAL_SIGNATURE_MASK_FLAGS,
            encoding);
        offset += 4;
        proto_tree_add_item(
            rtps_parameter_tree,
            hf_rtps_param_participant_security_digital_signature_algorithms_auth_used_bit,
            tvb,
            offset,
            4,
            encoding);
      break;
    }

    default: {
      return FALSE;
    }
  }/* End of switch for parameters for vendor RTI */
  return TRUE;
}

static gboolean dissect_parameter_sequence_toc(proto_tree *rtps_parameter_tree, packet_info *pinfo _U_,
    tvbuff_t *tvb, proto_item *parameter_item _U_, proto_item *param_len_item _U_, gint offset,
    const guint encoding, int param_length _U_,
    guint16 parameter) {

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
    case PID_TYPECODE_RTPS2: {
      rtps_util_add_typecode(rtps_parameter_tree,
        tvb,
        offset,
        encoding,
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
                 }

    default:
      return FALSE;
    }
  return TRUE;
}

static gboolean dissect_parameter_sequence_adl(proto_tree *rtps_parameter_tree _U_, packet_info *pinfo _U_,
    tvbuff_t *tvb _U_, proto_item *parameter_item _U_, proto_item *param_len_item _U_, gint offset _U_,
    const guint encoding _U_, int param_length _U_,
    guint16 parameter) {

  switch(parameter) {

    case PID_ADLINK_WRITER_INFO: {
      break;
    }
    case PID_ADLINK_READER_DATA_LIFECYCLE: {
      break;
    }
    case PID_ADLINK_WRITER_DATA_LIFECYCLE: {
      break;
    }
    case PID_ADLINK_ENDPOINT_GUID: {
      break;
    }
    case PID_ADLINK_SYNCHRONOUS_ENDPOINT: {
      break;
    }
    case PID_ADLINK_RELAXED_QOS_MATCHING: {
      break;
    }
    case PID_ADLINK_PARTICIPANT_VERSION_INFO: {
      break;
    }
    case PID_ADLINK_NODE_NAME: {
      break;
    }
    case PID_ADLINK_EXEC_NAME: {
      break;
    }
    case PID_ADLINK_PROCESS_ID: {
      break;
    }
    case PID_ADLINK_SERVICE_TYPE: {
      break;
    }
    case PID_ADLINK_ENTITY_FACTORY: {
      break;
    }
    case PID_ADLINK_WATCHDOG_SCHEDULING: {
      break;
    }
    case PID_ADLINK_LISTENER_SCHEDULING: {
      break;
    }
    case PID_ADLINK_SUBSCRIPTION_KEYS: {
      break;
    }
    case PID_ADLINK_READER_LIFESPAN: {
      break;
    }
    case PID_ADLINK_SHARE: {
      break;
    }
    case PID_ADLINK_TYPE_DESCRIPTION: {
      break;
    }
    case PID_ADLINK_LAN_ID: {
      break;
    }
    case PID_ADLINK_ENDPOINT_GID: {
      break;
    }
    case PID_ADLINK_GROUP_GID: {
      break;
    }
    case PID_ADLINK_EOTINFO: {
      break;
    }
    case PID_ADLINK_PART_CERT_NAME: {
      break;
    }
    case PID_ADLINK_LAN_CERT_NAME: {
      break;
    }
    default:
      return FALSE;
    }
  return TRUE;
}


static gboolean dissect_parameter_sequence_v1(proto_tree *rtps_parameter_tree, packet_info *pinfo, tvbuff_t *tvb,
    proto_item *parameter_item, proto_item * param_len_item, gint offset,
    const guint encoding, int size, int param_length,
    guint16 parameter, guint16 version, type_mapping * type_mapping_object,
    coherent_set_entity_info *coherent_set_entity_info_object) {

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
      rtps_util_add_timestamp_sec_and_fraction(rtps_parameter_tree, tvb, offset, encoding,
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
      rtps_util_add_timestamp_sec_and_fraction(rtps_parameter_tree, tvb, offset, encoding,
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
    case PID_TOPIC_NAME: {
      const gchar * retVal = NULL;
      guint32 str_size = tvb_get_guint32(tvb, offset, encoding);

      retVal = (gchar*)tvb_get_string_enc(wmem_packet_scope(), tvb, offset+4, str_size, ENC_ASCII);

      rtps_util_store_type_mapping(pinfo, tvb, offset, type_mapping_object,
          retVal, TOPIC_INFO_ADD_TOPIC_NAME);

      rtps_util_add_string(rtps_parameter_tree, tvb, offset, hf_rtps_param_topic_name, encoding);
      break;
    }

    /* 0...2...........7...............15.............23...............31
     * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     * | PID_OWNERSHIP_STRENGTH        |            0x0004             |
     * +---------------+---------------+---------------+---------------+
     * |    long              strength                                 |
     * +---------------+---------------+---------------+---------------+
     */
    case PID_OWNERSHIP_STRENGTH:
      ENSURE_LENGTH(4);
      proto_tree_add_item(rtps_parameter_tree, hf_rtps_param_strength, tvb, offset, 4, encoding);
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
    case PID_TYPE_NAME: {
      const gchar * retVal = NULL;
      guint32 str_size = tvb_get_guint32(tvb, offset, encoding);

      retVal = (gchar*) tvb_get_string_enc(wmem_packet_scope(), tvb, offset+4, str_size, ENC_ASCII);

      rtps_util_store_type_mapping(pinfo, tvb, offset, type_mapping_object,
          retVal, TOPIC_INFO_ADD_TYPE_NAME);

      rtps_util_add_string(rtps_parameter_tree, tvb, offset, hf_rtps_param_type_name, encoding);
      break;
    }

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
      rtps_util_add_port(rtps_parameter_tree, pinfo, tvb, offset, encoding, hf_rtps_param_port);
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
                                    encoding, hf_param_ip_address);
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
      rtps_util_add_vendor_id(rtps_parameter_tree, tvb, offset);
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
      proto_tree_add_item(rtps_parameter_tree, hf_rtps_reliability_kind, tvb, offset, 4, encoding);
      /* Older version of the protocol (and for PID_RELIABILITY_OFFERED)
       * this parameter was carrying also a NtpTime called
       * 'maxBlockingTime'.
       */
      if (size == 12) {
        rtps_util_add_timestamp(rtps_parameter_tree, tvb, offset + 4,
                    encoding, hf_rtps_reliability_max_blocking_time);
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
      rtps_util_add_liveliness_qos(rtps_parameter_tree, tvb, offset, encoding);
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
      proto_tree_add_item(rtps_parameter_tree, hf_rtps_durability, tvb, offset, 4, encoding);
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
      rtps_util_add_durability_service_qos(rtps_parameter_tree, tvb, offset, encoding);
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
      proto_tree_add_item(rtps_parameter_tree, hf_rtps_ownership, tvb, offset, 4, encoding);
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
      proto_tree_add_item(rtps_parameter_tree, hf_rtps_presentation_access_scope, tvb, offset, 4, encoding);
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
      rtps_util_add_timestamp_sec_and_fraction(rtps_parameter_tree, tvb, offset, encoding, hf_rtps_deadline_period);
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
      proto_tree_add_item(rtps_parameter_tree, hf_rtps_destination_order, tvb, offset, 4, encoding);
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
      rtps_util_add_timestamp_sec_and_fraction(rtps_parameter_tree, tvb, offset,
                    encoding, hf_rtps_latency_budget_duration);
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
      rtps_util_add_seq_string(rtps_parameter_tree, tvb, offset, encoding,
                               hf_rtps_param_partition_num, hf_rtps_param_partition, "name");
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
      rtps_util_add_timestamp_sec_and_fraction(rtps_parameter_tree, tvb, offset, encoding,
                             hf_rtps_lifespan_duration);
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
      rtps_util_add_seq_octets(rtps_parameter_tree, pinfo, tvb, offset,
                    encoding, param_length, hf_rtps_param_user_data);
      break;

    /* 0...2...........7...............15.............23...............31
     * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     * | PID_GROUP_DATA                |             length            |
     * +---------------+---------------+---------------+---------------+
     * |    unsigned long     sequence_size                            |
     * +---------------+---------------+---------------+---------------+
     * |   octet[0]    |   octet[1]    |   octet[2 ]   |   octet[3]    |
     * +---------------+---------------+---------------+---------------+
     * |                              ...                              |
     * +---------------+---------------+---------------+---------------+
     */
    case PID_GROUP_DATA:
      ENSURE_LENGTH(4);
      rtps_util_add_seq_octets(rtps_parameter_tree, pinfo, tvb, offset,
                    encoding, param_length, hf_rtps_param_group_data);
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
      rtps_util_add_seq_octets(rtps_parameter_tree, pinfo, tvb, offset,
                    encoding, param_length, hf_rtps_param_topic_data);
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
                    offset, encoding, "locator");
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
                    offset, encoding, "locator");
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
                              encoding, "locator");
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
                              encoding, "locator");
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
                    offset, encoding, "locator");
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
      proto_tree_add_item(rtps_parameter_tree, hf_rtps_participant_builtin_endpoints, tvb, offset, 4, encoding);
      break;

    case PID_PARTICIPANT_MANUAL_LIVELINESS_COUNT:
      ENSURE_LENGTH(4);
      proto_tree_add_item(rtps_parameter_tree, hf_rtps_participant_manual_liveliness_count, tvb, offset, 4, encoding);
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
      proto_tree_add_item(rtps_parameter_tree, hf_rtps_history_kind, tvb, offset, 4, encoding);
      proto_tree_add_item(rtps_parameter_tree, hf_rtps_history_depth, tvb, offset+4, 4, encoding);
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
      subtree = proto_tree_add_subtree(rtps_parameter_tree, tvb, offset, 12, ett_rtps_resource_limit, NULL, "Resource Limit");
      proto_tree_add_item(subtree, hf_rtps_resource_limit_max_samples, tvb, offset, 4, encoding);
      proto_tree_add_item(subtree, hf_rtps_resource_limit_max_instances, tvb, offset+4, 4, encoding);
      proto_tree_add_item(subtree, hf_rtps_resource_limit_max_samples_per_instances, tvb, offset+8, 4, encoding);
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
     * String1: ContentFilterTopicName
     * String2: RelatedTopicName
     * String3: FilterClassName
     * String4: FilterExpression
     * ExpressionParameters: sequence of Strings
     *
     * Note: those strings starts all to a word-aligned (4 bytes) offset
     */
    case PID_CONTENT_FILTER_PROPERTY: {
      guint32 temp_offset = offset;
      ENSURE_LENGTH(20);
      temp_offset = rtps_util_add_string(rtps_parameter_tree, tvb, temp_offset,
                    hf_rtps_param_content_filter_topic_name, encoding);
      temp_offset = rtps_util_add_string(rtps_parameter_tree, tvb, temp_offset,
                    hf_rtps_param_related_topic_name, encoding);
      temp_offset = rtps_util_add_string(rtps_parameter_tree, tvb, temp_offset,
                    hf_rtps_param_filter_class_name, encoding);
      temp_offset = rtps_util_add_string(rtps_parameter_tree, tvb, temp_offset,
                    hf_rtps_param_filter_expression, encoding);
      /*temp_offset = */rtps_util_add_seq_string(rtps_parameter_tree, tvb, temp_offset,
                    encoding, hf_rtps_param_expression_parameters_num,
                    hf_rtps_param_expression_parameters, "expressionParameters");
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
        guint32 temp_offset, prop_size;
        const guint8 *propName, *propValue;
        proto_item *list_item, *item;
        proto_tree *property_list_tree, *property_tree;
        guint32 seq_size = tvb_get_guint32(tvb, offset, encoding);
        int start_offset = offset, str_length;

        proto_item_append_text( parameter_item, " (%d properties)", seq_size );
        if (seq_size > 0) {
          property_list_tree = proto_tree_add_subtree(rtps_parameter_tree, tvb, offset, -1, ett_rtps_property_list, &list_item, "Property List");

          temp_offset = offset+4;
          while(seq_size-- > 0) {
            prop_size = tvb_get_guint32(tvb, temp_offset, encoding);
            propName = tvb_get_string_enc(wmem_packet_scope(), tvb, temp_offset+4, prop_size, ENC_ASCII);

            /* NDDS align strings at 4-bytes word. */
            str_length = (4 + ((prop_size + 3) & 0xfffffffc));
            item = proto_tree_add_string(property_list_tree, hf_rtps_property_name, tvb, temp_offset, str_length, propName);
            property_tree = proto_item_add_subtree(item, ett_rtps_property);
            temp_offset += str_length;

            prop_size = tvb_get_guint32(tvb, temp_offset, encoding);
            propValue = tvb_get_string_enc(wmem_packet_scope(), tvb, temp_offset+4, prop_size, ENC_ASCII);

            /* NDDS align strings at 4-bytes word. */
            str_length = (4 + ((prop_size + 3) & 0xfffffffc));
            proto_tree_add_string(property_tree, hf_rtps_property_value, tvb, temp_offset, str_length, propValue);
            temp_offset += str_length;
          }

          proto_item_set_len(list_item, temp_offset-start_offset);
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
      guint32 temp_offset;
      guint32 prev_offset;
      guint32 fs_elem;
      guint32 fs[4];
      ENSURE_LENGTH(8);

      /* Dissect filter bitmap */
      temp_offset = rtps_util_add_seq_ulong(rtps_parameter_tree, tvb, offset,
                        hf_rtps_filter_bitmap, encoding, param_length, "filterBitmap");

      /* Dissect sequence of FILTER_SIGNATURE */
      fs_elem = tvb_get_guint32(tvb, temp_offset, encoding);
      temp_offset += 4;
      while (fs_elem-- > 0) {
          prev_offset = temp_offset;
          /* Dissect the next FILTER_SIGNATURE object */
          fs[0] = tvb_get_guint32(tvb, temp_offset, encoding);
          temp_offset += 4;
          fs[1] = tvb_get_guint32(tvb, temp_offset, encoding);
          temp_offset += 4;
          fs[2] = tvb_get_guint32(tvb, temp_offset, encoding);
          temp_offset += 4;
          fs[3] = tvb_get_guint32(tvb, temp_offset, encoding);
          temp_offset += 4;
          proto_tree_add_bytes_format_value(rtps_parameter_tree, hf_rtps_filter_signature, tvb, prev_offset, temp_offset - prev_offset, NULL, "%08x %08x %08x %08x",
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
    case PID_COHERENT_SET: {
      guint64 coherent_seq_number;

      ENSURE_LENGTH(8);
      coherent_seq_number = rtps_util_add_seq_number(rtps_parameter_tree, tvb, offset,
        encoding, "sequenceNumber");
      if (coherent_set_entity_info_object && rtps_parameter_tree) {
        rtps_util_add_coherent_set_general_cases_case(rtps_parameter_tree,
          tvb, coherent_seq_number, coherent_set_entity_info_object);
      }
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
      rtps_util_add_typecode(rtps_parameter_tree, tvb, offset, encoding,
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
                    hf_rtps_participant_guid_v1, hf_rtps_param_host_id, hf_rtps_param_app_id,
                    hf_rtps_param_instance_id_v1, hf_rtps_param_app_kind,
                    hf_rtps_param_entity, hf_rtps_param_entity_key, hf_rtps_param_hf_entity_kind);
      } else {
        ENSURE_LENGTH(16);
        rtps_util_add_generic_guid_v2(rtps_parameter_tree, tvb, offset,
                    hf_rtps_participant_guid, hf_rtps_param_host_id, hf_rtps_param_app_id,
                    hf_rtps_param_instance_id, hf_rtps_param_entity, hf_rtps_param_entity_key,
                    hf_rtps_param_hf_entity_kind, NULL);
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
                    hf_rtps_group_guid_v1, hf_rtps_param_host_id, hf_rtps_param_app_id,
                    hf_rtps_param_instance_id_v1, hf_rtps_param_app_kind,
                    hf_rtps_param_entity, hf_rtps_param_entity_key, hf_rtps_param_hf_entity_kind);
      } else {
        ENSURE_LENGTH(16);
        rtps_util_add_generic_guid_v2(rtps_parameter_tree, tvb, offset,
                    hf_rtps_group_guid, hf_rtps_param_host_id, hf_rtps_param_app_id,
                    hf_rtps_param_instance_id, hf_rtps_param_entity, hf_rtps_param_entity_key,
                    hf_rtps_param_hf_entity_kind, NULL);
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
      rtps_util_add_timestamp_sec_and_fraction(rtps_parameter_tree, tvb, offset, encoding,
                        hf_rtps_persistence);
      break;

    case PID_TYPE_CHECKSUM:
      ENSURE_LENGTH(4);
      proto_tree_add_checksum(rtps_parameter_tree, tvb, offset, hf_rtps_type_checksum, -1, NULL, pinfo, 0, encoding, PROTO_CHECKSUM_NO_FLAGS);
      break;

    case PID_EXPECTS_ACK:
      ENSURE_LENGTH(1);
      proto_tree_add_item(rtps_parameter_tree, hf_rtps_expects_ack, tvb, offset, 1, ENC_NA );
      break;

    case PID_MANAGER_KEY: {
      int i = 0;
      guint32 manager_key;

      subtree = proto_tree_add_subtree(rtps_parameter_tree, tvb, offset, param_length, ett_rtps_manager_key, NULL, "Manager Keys");

      while (param_length >= 4) {
        manager_key = tvb_get_guint32(tvb, offset, encoding);
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
      proto_tree_add_item(rtps_parameter_tree, hf_rtps_queue_size, tvb, offset, 4, encoding);
      break;

    case PID_VARGAPPS_SEQUENCE_NUMBER_LAST:
      ENSURE_LENGTH(4);
      rtps_util_add_seq_number(rtps_parameter_tree, tvb, offset, encoding, "sequenceNumberLast");
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
    case PID_TYPE2_NAME:
    case PID_TYPE2_CHECKSUM:
    case PID_RELIABILITY_ENABLED:
      expert_add_info(pinfo, parameter_item, &ei_rtps_parameter_not_decoded);
      /* Fall Through */
    case PID_PAD:
      if (param_length > 0) {
        proto_tree_add_item(rtps_parameter_tree, hf_rtps_parameter_data, tvb,
                        offset, param_length, ENC_NA);
      }
      break;

    default:
      return FALSE;
  }

  return TRUE;
}

static gboolean dissect_parameter_sequence_v2(proto_tree *rtps_parameter_tree, packet_info *pinfo, tvbuff_t *tvb,
                        proto_item *parameter_item _U_, proto_item *param_len_item,
                        gint offset, const guint encoding, int param_length,
                        guint16 parameter, guint32 *pStatusInfo, guint16 vendor_id _U_,
                        type_mapping * type_mapping_object,
                        coherent_set_entity_info *coherent_set_entity_info_object _U_) {
  proto_item *ti;

  switch(parameter) {
    /* 0...2...........7...............15.............23...............31
     * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     * | PID_STATUS_INFO               |            0x0004             |
     * +---------------+---------------+---------------+---------------+
     * |    long              statusInfo                               |
     * +---------------+---------------+---------------+---------------+
     */
    case PID_STATUS_INFO: {
      ENSURE_LENGTH(4);
      /* PID_STATUS_INFO is always coded in network byte order (big endian) */
      proto_tree_add_bitmask(rtps_parameter_tree, tvb, offset,
              hf_rtps_param_status_info_flags, ett_rtps_flags,
              STATUS_INFO_FLAGS, ENC_BIG_ENDIAN);
      if (pStatusInfo != NULL) {
        *pStatusInfo = tvb_get_ntohl(tvb, offset);
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
      ENSURE_LENGTH(16);
      rtps_util_add_guid_prefix_v2(rtps_parameter_tree, tvb, offset, hf_rtps_sm_guid_prefix,
                    hf_rtps_sm_host_id, hf_rtps_sm_app_id, hf_rtps_sm_instance_id, 0);
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
    ti = proto_tree_add_bytes_format(rtps_parameter_tree, hf_rtps_guid, tvb, offset, param_length, NULL, "guid: ");
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
      proto_tree_add_item(rtps_parameter_tree, hf_rtps_param_transport_priority, tvb, offset, 4, encoding);
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
      guint32 temp_offset;
      guint32 prev_offset;
      guint32 fs_elem;
      guint32 fs[4];
      ENSURE_LENGTH(8);

      /* Dissect filter bitmap */
      temp_offset = rtps_util_add_seq_ulong(rtps_parameter_tree, tvb, offset,
                    hf_rtps_filter_bitmap, encoding, param_length, "filterBitmap");

      /* Dissect sequence of FILTER_SIGNATURE */
      fs_elem = tvb_get_guint32(tvb, temp_offset, encoding);
      temp_offset += 4;
      while (fs_elem-- > 0) {
        prev_offset = temp_offset;
        /* Dissect the next FILTER_SIGNATURE object */
        fs[0] = tvb_get_guint32(tvb, temp_offset, encoding);
        temp_offset += 4;
        fs[1] = tvb_get_guint32(tvb, temp_offset, encoding);
        temp_offset += 4;
        fs[2] = tvb_get_guint32(tvb, temp_offset, encoding);
        temp_offset += 4;
        fs[3] = tvb_get_guint32(tvb, temp_offset, encoding);
        temp_offset += 4;
        proto_tree_add_bytes_format_value(rtps_parameter_tree, hf_rtps_filter_signature, tvb, prev_offset, temp_offset - prev_offset, NULL, "%08x %08x %08x %08x",
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
    case PID_BUILTIN_ENDPOINT_SET: {
      guint32 flags;
      ENSURE_LENGTH(4);
      flags = tvb_get_guint32(tvb, offset, encoding);
      proto_tree_add_bitmask_value(rtps_parameter_tree, tvb, offset,
              hf_rtps_param_builtin_endpoint_set_flags, ett_rtps_flags,
              BUILTIN_ENDPOINT_FLAGS, flags);
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
      proto_tree_add_item(rtps_parameter_tree, hf_rtps_param_type_max_size_serialized, tvb, offset, 4, encoding);
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
                    hf_rtps_sm_host_id, hf_rtps_sm_app_id, hf_rtps_sm_instance_id, 0);
      rtps_util_add_entity_id(rtps_parameter_tree, tvb, offset+12, hf_rtps_sm_entity_id,
                    hf_rtps_sm_entity_id_key, hf_rtps_sm_entity_id_kind, ett_rtps_entity,
                    "virtualGUIDSuffix", NULL);

      /* Sequence number */
      rtps_util_add_seq_number(rtps_parameter_tree, tvb, offset+16,
                            encoding, "virtualSeqNumber");
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
      rtps_util_add_string(rtps_parameter_tree, tvb, offset, hf_rtps_param_entity_name, encoding);
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
      rtps_util_store_type_mapping(pinfo, tvb, offset, type_mapping_object,
          NULL, TOPIC_INFO_ADD_GUID);
      rtps_util_add_generic_guid_v2(rtps_parameter_tree, tvb, offset,
                    hf_rtps_endpoint_guid, hf_rtps_param_host_id, hf_rtps_param_app_id,
                    hf_rtps_param_instance_id, hf_rtps_param_entity, hf_rtps_param_entity_key,
                    hf_rtps_param_hf_entity_kind, NULL);
      break;


   /* 0...2...........7...............15.............23...............31
    * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    * | PID_DATA_REPRESENTATION       |             length            |
    * +---------------+---------------+---------------+---------------+
    * | uint32 SequenceSize                                           |
    * +---------------+---------------+---------------+---------------+
    * | int16 DataRepresentationId[0] | int16 DataRepresentationId[1] |
    * +---------------+-------------------------------+---------------+
    * | ...                           | int16 DataRepresentationId[N] |
    * +---------------+---------------+---------------+---------------+
    */
    case PID_DATA_REPRESENTATION: {
      proto_tree *data_representation_seq_subtree;
      proto_item *item;
      guint value;
      guint item_offset;
      guint seq_size;
      guint counter = 0;

      seq_size = tvb_get_guint32(tvb, offset, encoding);
      data_representation_seq_subtree = proto_tree_add_subtree_format(rtps_parameter_tree, tvb, offset,
        param_length, ett_rtps_data_representation, &item, "Data Representation Sequence[%d]", seq_size);
      item_offset = offset + 4;
      for (; counter < seq_size; ++counter) {
        value = tvb_get_guint16(tvb, item_offset, encoding);
        proto_tree_add_uint_format(data_representation_seq_subtree, hf_rtps_param_data_representation,
          tvb, item_offset, 2, value, "[%d]: %s (0x%X)", counter,
          val_to_str(value, data_representation_kind_vals, "Unknown data representation value: %u"),
          value);
        item_offset += 2;
      }
      break;
    }
    /* This parameter PID serializes a sequence number like the existing PID_COHERENT_SET */
    /* 0...2...........7...............15.............23...............31
    * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    * | PID_GROUP_COHERENT_SET        |            length             |
    * +---------------+---------------+---------------+---------------+
    * |                                                               |
    * + SequenceNumber seqNumber                                      +
    * |                                                               |
    * +---------------+---------------+---------------+---------------+
    */
    case PID_GROUP_COHERENT_SET: {
        guint64 hi = (guint64)tvb_get_guint32(tvb, offset, encoding);
        guint64 lo = (guint64)tvb_get_guint32(tvb, offset + 4, encoding);
        guint64 all = (hi << 32) | lo;

        proto_tree_add_uint64(
                rtps_parameter_tree,
                hf_rtps_param_group_coherent_set,
                tvb, offset,
                sizeof(guint64),
                all);
        break;
    }
    /* This parameter serializes a sequence number like the existing PID_COHERENT_SET
     * and only applies to an end coherent set sample.
     */
     /* 0...2...........7...............15.............23...............31
     * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     * | PID_END_GROUP_COHERENT_SET    |            length             |
     * +---------------+---------------+---------------+---------------+
     * |                                                               |
     * + SequenceNumber seqNumber                                      +
     * |                                                               |
     * +---------------+---------------+---------------+---------------+
     */
    case PID_END_GROUP_COHERENT_SET: {
        guint64 hi = (guint64)tvb_get_guint32(tvb, offset, encoding);
        guint64 lo = (guint64)tvb_get_guint32(tvb, offset + 4, encoding);
        guint64 all = (hi << 32) | lo;

        proto_tree_add_uint64(
            rtps_parameter_tree,
            hf_rtps_param_end_group_coherent_set,
            tvb, offset,
            sizeof(guint64),
            all);
        break;
    }
    /* This parameter serializes a SN like the existing PID_COHERENT_SET and
     * only applies to an end coherent set sample.
     * Since there are different ways to finish a coherent set it is necessary
     * to store information about the available coherent sets. this PID requires
     * set the corrresponding coherence set as "is_set".
     */
     /* 0...2...........7...............15.............23...............31
     * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     * | PID_END_COHERENT_SET          |            length             |
     * +---------------+---------------+---------------+---------------+
     * |                                                               |
     * + SequenceNumber seqNumber                                      +
     * |                                                               |
     * +---------------+---------------+---------------+---------------+
     */
    case PID_END_COHERENT_SET: {

        coherent_set_key coherent_set_info_key;
        guint64 coherent_seq_number = 0;
        coherent_set_entity_info *register_entry = NULL;
        coherent_set_info *coherent_set_info_entry;

        coherent_seq_number = rtps_util_add_seq_number(
                rtps_parameter_tree,
                tvb,
                offset,
                encoding,
                "coherenceSetSequenceNumber");
        ti = proto_tree_add_uint64(
                rtps_parameter_tree,
                hf_rtps_coherent_set_end,
                tvb,
                0,
                0,
                coherent_seq_number);
        proto_item_set_generated(ti);
        /* Need to finish the stored coherence set */
        if (coherent_set_entity_info_object != NULL) {
            register_entry = (coherent_set_entity_info*)wmem_map_lookup(
                    coherent_set_tracking.entities_using_map,
                    &coherent_set_entity_info_object->guid);
            if (register_entry) {
                register_entry->coherent_set_seq_number = coherent_seq_number;
                memset(&coherent_set_info_key, 0, sizeof(coherent_set_info_key));
                coherent_set_info_key.guid = register_entry->guid;
                coherent_set_info_key.coherent_set_seq_number = register_entry->coherent_set_seq_number;
                coherent_set_info_entry = (coherent_set_info*)wmem_map_lookup(
                        coherent_set_tracking.coherent_set_registry_map,
                        &coherent_set_info_key);
                if (coherent_set_info_entry) {
                    /* The coherence set is completely set up */
                    coherent_set_info_entry->is_set = TRUE;
                    /* Updating by last time the writer_seq_number */
                    coherent_set_info_entry->writer_seq_number = coherent_set_entity_info_object->writer_seq_number;
                }
            }
        }
        break;
    }
    /* This parameter serializes a long (4-byte integer) and only applies to an end coherent set sample */
    /* 0...2...........7...............15.............23...............31
    * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    * | MIG..._SET_SAMPLE_COUNT       |            length             |
    * +---------------+---------------+---------------+---------------+
    * + sampleCount                                                   +
    * +---------------+---------------+---------------+---------------+
    */
    case MIG_RTPS_PID_END_COHERENT_SET_SAMPLE_COUNT: {
        guint32 sample_count = tvb_get_guint32(tvb, offset, encoding);

        proto_tree_add_uint(
            rtps_parameter_tree,
            hf_rtps_param_mig_end_coherent_set_sample_count,
            tvb, offset,
            sizeof(guint32),
            sample_count);
        break;
    }

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
    case PID_DEFAULT_MULTICAST_LOCATOR: {
      ENSURE_LENGTH(24);
      rtps_util_add_locator_t(rtps_parameter_tree, pinfo, tvb, offset, encoding, "locator");
      break;
    }

    default:
        return FALSE;
  } /* End of switch(parameter) */

  return TRUE;
}
#undef ENSURE_LENGTH

static gint dissect_parameter_sequence(proto_tree *tree, packet_info *pinfo, tvbuff_t *tvb,
    gint offset, const guint encoding, guint size, const char *label,
    guint16 version, guint32 *pStatusInfo, guint16 vendor_id,
    gboolean is_inline_qos, coherent_set_entity_info *coherent_set_entity_info_object) {

  proto_item *ti, *param_item, *param_len_item = NULL;
  proto_tree *rtps_parameter_sequence_tree, *rtps_parameter_tree;
  guint32    parameter, param_length, param_length_length = 2;
  gint       original_offset = offset, initial_offset = offset;
  type_mapping * type_mapping_object = NULL;
  const gchar * param_name = NULL;
  if (!pinfo->fd->visited) {
    /*
     * At minimum, type_mapping_object->fields_visited must be
     * initialized to 0, because we haven't visited any fields
     * yet.  The routines that visit fields just set individual
     * bits in type_mapping_object->fields_visited; they don't
     * initialize it.
     */
    type_mapping_object = wmem_new(wmem_file_scope(), type_mapping);
    type_mapping_object->fields_visited = 0;
    type_mapping_object->guid.fields_present = 0;
  }

  rtps_parameter_sequence_tree = proto_tree_add_subtree_format(tree, tvb, offset, size,
          ett_rtps_parameter_sequence, &ti, "%s:", label);

  /* Loop through all the parameters defined until PID_SENTINEL is found */
  for (;;) {
    size -= offset - original_offset;
    if (size < 4) {
      expert_add_info_format(pinfo, (param_len_item == NULL) ? ti : param_len_item,
              &ei_rtps_parameter_value_invalid, "ERROR: not enough bytes to read the next parameter");
      return 0;
    }
    original_offset = offset;

    /* Reads parameter and create the sub tree. At this point we don't know
     * the final string that will identify the node or its length. It will
     * be set later...
     */
    parameter = tvb_get_guint16(tvb, offset, encoding);
    param_length = tvb_get_guint16(tvb, offset+2, encoding);
    if ((parameter & PID_EXTENDED) == PID_EXTENDED) {
      offset += 4;
      /* get extended member id and length */
      parameter = tvb_get_guint32(tvb, offset, encoding);
      param_length = tvb_get_guint32(tvb, offset+4, encoding);
      param_length_length = 4;
    }
    if (version < 0x0200) {
      rtps_parameter_tree = proto_tree_add_subtree(rtps_parameter_sequence_tree, tvb, offset, -1,
                        ett_rtps_parameter, &param_item, val_to_str(parameter, parameter_id_vals, "Unknown (0x%04x)"));

      proto_tree_add_uint(rtps_parameter_tree, hf_rtps_parameter_id, tvb, offset, 2, parameter);
    } else {
      gboolean goto_default = TRUE;
      switch(vendor_id) {
        case RTPS_VENDOR_RTI_DDS:
        case RTPS_VENDOR_RTI_DDS_MICRO: {
          if (is_inline_qos) {
            param_name = try_val_to_str(parameter, parameter_id_inline_qos_rti);
            if (param_name != NULL) {
              rtps_parameter_tree = proto_tree_add_subtree(rtps_parameter_sequence_tree, tvb, offset, -1,
                ett_rtps_parameter, &param_item, val_to_str(parameter, parameter_id_inline_qos_rti, "Unknown (0x%04x)"));
              proto_tree_add_uint(rtps_parameter_tree, hf_rtps_parameter_id_inline_rti, tvb, offset,
                      param_length_length, parameter);
              goto_default = FALSE;
            }
          } else {
            param_name = try_val_to_str(parameter, parameter_id_rti_vals);
            if (param_name != NULL) {
              rtps_parameter_tree = proto_tree_add_subtree(rtps_parameter_sequence_tree, tvb, offset, -1,
                        ett_rtps_parameter, &param_item, val_to_str(parameter, parameter_id_rti_vals, "Unknown (0x%04x)"));
              proto_tree_add_uint(rtps_parameter_tree, hf_rtps_parameter_id_rti, tvb, offset,
                      param_length_length, parameter);
              goto_default = FALSE;
            }
          }
          break;
        }
        case RTPS_VENDOR_TOC: {
          param_name = try_val_to_str(parameter, parameter_id_toc_vals);
          if (param_name != NULL) {
            rtps_parameter_tree = proto_tree_add_subtree(rtps_parameter_sequence_tree, tvb, offset, -1,
                  ett_rtps_parameter, &param_item, val_to_str(parameter, parameter_id_toc_vals, "Unknown (0x%04x)"));

            proto_tree_add_uint(rtps_parameter_tree, hf_rtps_parameter_id_toc, tvb, offset,
                    param_length_length, parameter);
            goto_default = FALSE;
          }
          break;
        }
        case RTPS_VENDOR_ADL_DDS: {
          param_name = try_val_to_str(parameter, parameter_id_adl_vals);
          if (param_name != NULL) {
            rtps_parameter_tree = proto_tree_add_subtree(rtps_parameter_sequence_tree, tvb, offset, -1,
                  ett_rtps_parameter, &param_item, val_to_str(parameter, parameter_id_adl_vals, "Unknown (0x%04x)"));

            proto_tree_add_uint(rtps_parameter_tree, hf_rtps_parameter_id_adl, tvb, offset,
                    param_length_length, parameter);
            goto_default = FALSE;
          }
          break;
        }
      }
      if (goto_default) {
        rtps_parameter_tree = proto_tree_add_subtree(rtps_parameter_sequence_tree, tvb, offset, -1,
            ett_rtps_parameter, &param_item, val_to_str(parameter, parameter_id_v2_vals, "Unknown (0x%04x)"));
        proto_tree_add_uint(rtps_parameter_tree, hf_rtps_parameter_id_v2, tvb, offset,
                param_length_length, parameter);
      }

    }
    /* after param_id */
    offset += param_length_length;

    if (parameter == PID_SENTINEL) {
      /* PID_SENTINEL closes the parameter list, (length is ignored) */
      proto_item_set_len(param_item, 4);
      offset += 2;
      proto_item_set_len(rtps_parameter_sequence_tree, offset - initial_offset);
      return offset;
    }

    /* parameter length */
    param_len_item = proto_tree_add_item(rtps_parameter_tree, hf_rtps_parameter_length,
                        tvb, offset, param_length_length, encoding);
    offset += param_length_length;

    /* Make sure we have enough bytes for the param value */
    if ((size-4 < param_length) &&
        (parameter != PID_SENTINEL)) {
      expert_add_info_format(pinfo, param_len_item, &ei_rtps_parameter_value_invalid, "Not enough bytes to read the parameter value");
      return 0;
    }

    /* Sets the end of this item (now we know it!) */
    proto_item_set_len(param_item, param_length+2*param_length_length);

    /* This way, we can include vendor specific dissections without modifying the main ones */

      if (!dissect_parameter_sequence_v1(rtps_parameter_tree, pinfo, tvb, param_item, param_len_item,
        offset, encoding, size, param_length, parameter, version, type_mapping_object, coherent_set_entity_info_object)) {
          if ((version < 0x0200) ||
            !dissect_parameter_sequence_v2(rtps_parameter_tree, pinfo, tvb, param_item, param_len_item,
            offset, encoding, param_length, parameter,
            pStatusInfo, vendor_id, type_mapping_object, coherent_set_entity_info_object)) {
              if (param_length > 0) {
                proto_tree_add_item(rtps_parameter_tree, hf_rtps_parameter_data, tvb,
                        offset, param_length, ENC_NA);
              }
          }
      }

    switch (vendor_id) {
      case RTPS_VENDOR_RTI_DDS:
      case RTPS_VENDOR_RTI_DDS_MICRO: {
        dissect_parameter_sequence_rti_dds(rtps_parameter_tree, pinfo, tvb,
            param_item, param_len_item, offset, encoding, param_length, parameter, type_mapping_object, is_inline_qos, vendor_id);
        break;
      }
      case RTPS_VENDOR_TOC: {
        dissect_parameter_sequence_toc(rtps_parameter_tree, pinfo, tvb,
            param_item, param_len_item, offset, encoding, param_length, parameter);
        break;
      }
      case RTPS_VENDOR_ADL_DDS: {
        dissect_parameter_sequence_adl(rtps_parameter_tree, pinfo, tvb,
            param_item, param_len_item, offset, encoding, param_length, parameter);
        break;
      }
      default:
        break;
    }

    rtps_util_insert_type_mapping_in_registry(pinfo, type_mapping_object);
    offset += param_length;
  }
  proto_item_set_len(ti, offset - initial_offset);
  return offset;
}

static gboolean rtps_is_ping(tvbuff_t *tvb, packet_info *pinfo, gint offset)
{
  gboolean is_ping = FALSE;

  if (!tvb_strneql(tvb, offset, "NDDSPING", 8))
    is_ping = TRUE;

  if (is_ping)
    col_set_str(pinfo->cinfo, COL_INFO, "PING");

  return is_ping;
}

/* *********************************************************************** */
/* *                        A P P_ A C K_ C O N F                        * */
/* *********************************************************************** */
static void dissect_APP_ACK_CONF(tvbuff_t *tvb,
  packet_info *pinfo _U_,
  gint offset,
  guint8 flags,
  const guint encoding,
  int octets_to_next_header,
  proto_tree *tree,
  proto_item *item,
  endpoint_guid * guid)
  {
  /*
  * 0...2...........7...............15.............23...............31
  * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  * |  APP_ACK_CONF |X|X|X|X|X|X|X|E|      octetsToNextHeader       |
  * +---------------+---------------+---------------+---------------+
  * | EntityId readerEntityId                                       |
  * +---------------+---------------+---------------+---------------+
  * | EntityId writerEntityId                                       |
  * +---------------+---------------+---------------+---------------+
  * + unsigned long virtualWriterCount                              +
  * +---------------+---------------+---------------+---------------+
  * | GuidPrefix  virtualWriterGuidPrefix                           |
  * +---------------+---------------+---------------+---------------+
  * EntityId virtualWriterObjectId
  *
  * (after last interval) unsigned long virtualWriterEpoch
  *
  */
  gint original_offset; /* Offset to the readerEntityId */
  gint32 virtual_writer_count;
  guint32 wid;
  proto_item *octet_item;
  proto_tree_add_bitmask_value(tree, tvb, offset + 1, hf_rtps_sm_flags, ett_rtps_flags, APP_ACK_CONF_FLAGS, flags);

  octet_item = proto_tree_add_item(tree, hf_rtps_sm_octets_to_next_header, tvb, offset + 2, 2, encoding);
  offset += 4;
  original_offset = offset;

  if (octets_to_next_header < 20) {
    expert_add_info_format(pinfo, octet_item, &ei_rtps_sm_octets_to_next_header_error, "(Error: should be >= %u)", 20);
    return;
  }

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
  guid->entity_id = wid;
  guid->fields_present |= GUID_HAS_ENTITY_ID;
  rtps_util_topic_info_add_tree(tree, tvb, offset, guid);


  /* virtualWriterCount */
  proto_tree_add_item_ret_uint(tree, hf_rtps_param_app_ack_conf_virtual_writer_count, tvb, offset, 4,
    encoding, &virtual_writer_count);
  offset += 4;

  {
    /* Deserialize Virtual Writers */
    proto_tree *sil_tree_writer_list;
    proto_tree *sil_tree_writer;

    gint32 current_writer_index = 0;

    /** Writer list **/

    sil_tree_writer_list = proto_tree_add_subtree_format(tree, tvb, offset, -1,
           ett_rtps_app_ack_virtual_writer_list, NULL, "Virtual Writer List");

    current_writer_index = 0;

    while (current_writer_index < virtual_writer_count) {
      sil_tree_writer = proto_tree_add_subtree_format(sil_tree_writer_list, tvb, offset, -1,
           ett_rtps_app_ack_virtual_writer, NULL, "virtualWriter[%d]", current_writer_index);

      /* Virtual Writer Guid */
      rtps_util_add_guid_prefix_v2(sil_tree_writer, tvb, offset,
        hf_rtps_sm_guid_prefix, hf_rtps_sm_host_id, hf_rtps_sm_app_id,
        hf_rtps_sm_instance_id, 0);

      rtps_util_add_entity_id(sil_tree_writer, tvb, offset+12,
        hf_rtps_sm_entity_id, hf_rtps_sm_entity_id_key, hf_rtps_sm_entity_id_kind,
        ett_rtps_entity, "virtualGUIDSuffix", NULL);

      offset += 16;

      /* Counter */
      proto_tree_add_item(tree, hf_rtps_param_app_ack_conf_count, tvb, offset, 4, encoding);
      offset += 4;

      current_writer_index++;

    } /* virtual_writer_count */
  }


  if (offset < original_offset + octets_to_next_header)
  {
    /* In this case there must be something wrong in the bitmap: there
    * are some extra bytes that we don't know how to decode
    */
    expert_add_info_format(pinfo, item, &ei_rtps_extra_bytes, "Don't know how to decode those extra bytes: %d", octets_to_next_header - offset);
  }
  else if (offset > original_offset + octets_to_next_header)
  {
    /* Decoding the bitmap went over the end of this submessage.
    * Enter an item in the protocol tree that spans over the entire
    * submessage.
    */
    expert_add_info(pinfo, item, &ei_rtps_missing_bytes);
  }
}

static void dissect_parametrized_serialized_data(proto_tree *tree, tvbuff_t *tvb,
                       gint offset_input, int size, const guint encoding)
{
  guint32 member_id, member_length;
  proto_item * ti;
  proto_tree * data_tree, * member_tree;
  gint offset = offset_input;
  gint deserialized_size = 0;
  data_tree = proto_tree_add_subtree_format(tree, tvb, offset, -1,
          ett_rtps_serialized_data, &ti, "serializedData");
  while (deserialized_size < size) {
    ALIGN_ZERO(offset, 2, offset_input);
    member_id = tvb_get_guint16(tvb, offset, encoding);
    member_length = tvb_get_guint16(tvb, offset+2, encoding);

    if ((member_id & PID_EXTENDED) == PID_EXTENDED) {
      member_id = tvb_get_guint32(tvb, offset+4, encoding);
      member_length = tvb_get_guint32(tvb, offset+8, encoding);
      member_tree = proto_tree_add_subtree_format(data_tree, tvb, offset, member_length + 12,
              ett_rtps_data_member, NULL, "Member (id = %u, len = %u)", member_id, member_length);
      proto_tree_add_item(member_tree, hf_rtps_pl_cdr_member_id_ext, tvb, offset+4, 4, encoding);
      proto_tree_add_item(member_tree, hf_rtps_pl_cdr_member_length_ext, tvb, offset+8, 4, encoding);
      offset += 12;
      deserialized_size += 12;
    } else if ((member_id & PID_LIST_END) == PID_LIST_END){
      /* If this is the end of the list, don't add a tree.
       * If we add more logic here in the future, take into account that
       * offset is incremented by 4 */
      deserialized_size += 4;
      break;
    } else {
        member_tree = proto_tree_add_subtree_format(data_tree, tvb, offset, member_length + 4,
              ett_rtps_data_member, NULL, "Member (id = %u, len = %u)", member_id, member_length);
      proto_tree_add_item(member_tree, hf_rtps_pl_cdr_member_id, tvb, offset, 2, encoding);
      proto_tree_add_item(member_tree, hf_rtps_pl_cdr_member_length, tvb, offset+2, 2, encoding);
      offset += 4;
      deserialized_size += 4;
    }

    proto_tree_add_item(member_tree, hf_rtps_pl_cdr_member, tvb, offset,
            member_length, encoding);
    offset += member_length;
    deserialized_size += member_length;
  }
  proto_item_set_len(ti, deserialized_size);
}

/************************************************************************ */
/* Encapsulated data                                                    * */
/* ********************************************************************** */
/*
 * Note: the encapsulation header is ALWAYS big endian, then the encapsulation
 * type specified the type of endianness of the payload.
 * 0...2...........8...............16..............24..............32
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *| representation_identifier | X X X X X X X X X X X | C C C P P |
 *+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *~                                                               ~
 * ~... Bytes of data representation using a format that ...      ~
 * ~... depends on the RepresentationIdentifier and options ...   ~
 * ~                                                              ~
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 *  X = Unused options bits
 *  C = Compression bits
 *  P = Padding bits
 *
 * If compressed:
 *  0...2...........8...............16..............24..............32
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * | representation_identifier | X X X X X X X X X X X | C C C P P |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * ~                    Uncompressed Length                        ~
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * ~                 *Extended Compression Options                 ~
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * ~                 Compressed User Data ...                      ~
 * ~                                                               ~
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 * C = 0b111 would be extended compression options which would come in as an
 *      additional header before the payload.
 * C = 0b000 to indicate no compression
 *
 * This options field would be used for future enhancements.For example,
 *  could be used to define a custom compressor plugin for matching purposes.
 */

 /* Dissects the encapsultaion header and uncompress the serialized
  *  data if is is compressed and it is compressed in using Zlib.
  *
  * @param[in] tree
  * @param[in] packet info.
  * @param[in] tvb
  * @param[in] offset offset at the begining of the encapsulation id.
  * @param[in] size in bytes from the initial offset to the end of the serialized data
  * @param[in] uncompress_if_compressed true for uncompressing if the data should be uncompressed.
  * @param[out] encapsulation_id_out If not null it will contain the encapsultaion_id
  * @param[out] compression_option_out If not null it will contain the compression option
  * @param[out] padding_bytes_out If not null it will contain the padding bytes
  * @param[out] extended_compression_options_out If not null it will contain the extended compression options
  * @param[out] extended_header_bits_out If not null it will contain the extended header bits
  * @param[out] is_compressed_out If not null it will indicate if the serielized data is compressed
  * @param[out] uncompressed_ok_out If not null it will indicate if the serizlized data has been succesfully uncompressed
  * @param[out] uncompressed_tvb_out If not null it will contain the uncompressed tvb pointer. If the seriaized data is not uncompressed it will return NULL.
  * @param[out] compressed_data_tree_out If not null it will contain the subtree of the uncompressed data.
  *
  * @return the offset after the at the beginining of the serialized data
  * @note All output parameters are optional.
  */
static
gint rtps_prepare_encapsulated_data(
        proto_tree *tree,
        packet_info *pinfo,
        tvbuff_t *tvb,
        gint offset,
        int  size,
        gboolean uncompress_if_compressed,
        guint16 *encapsulation_id_out,
        guint8 *compression_option_out,
        guint8 *padding_bytes_out,
        guint32 *extended_compression_options_out,
        guint8 *extended_header_bits_out,
        gboolean *is_compressed_out,
        gboolean *uncompressed_ok_out,
        tvbuff_t **uncompressed_tvb_out,
        proto_tree **compressed_data_tree_out) {
    gint initial_offset = offset;
    gint16 encapsulation_options = 0;
    guint32 compressed_size = 0;
    guint32 uncompressed_size = 0;
    guint16 encapsulation_id = 0;
    guint8 compression_option = 0;
    guint8 padding_bytes = 0;
    guint32 extended_compression_options = 0;
    guint8 extended_header_bits = 0;
    gboolean is_compressed = 0;
    gboolean uncompressed_ok = 0;
    tvbuff_t *uncompressed_tvb = NULL;

    /* This logic applies to data that is not a fragment (-1) or is the first fragment */
    /* Encapsulation ID */
    encapsulation_id = tvb_get_ntohs(tvb, offset);   /* Always big endian */
    proto_tree_add_uint(tree,
        hf_rtps_param_serialize_encap_kind, tvb, offset, 2, encapsulation_id);
    offset += 2;

    offset = rtps_util_dissect_encapsulation_options(
            tree,
            tvb,
            offset,
            &encapsulation_options,
            &compression_option,
            &padding_bytes,
            &extended_header_bits);
    /* If compressed on a supported format we have to  uncompress it on a new tvb
    * and reset the offset */
    is_compressed = (encapsulation_options & ENCAPSULATION_OPTIONS_COMPRESSION_BYTES_MASK) != 0;
    if (is_compressed) {
        uncompressed_size = tvb_get_gint32(tvb, offset, ENC_BIG_ENDIAN);
        proto_tree_add_item(
                tree,
                hf_rtps_uncompressed_serialized_length,
                tvb,
                offset,
                4,
                ENC_BIG_ENDIAN);
        offset += 4;
        /* Get the compression extended options if required */
        if (extended_header_bits == ENCAPSULATION_OPTIONS_COMPRESSION_EXTENDED_HEADER_VALUE) {
            extended_compression_options = tvb_get_gint32(tvb, offset, ENC_BIG_ENDIAN);
            proto_tree_add_item(
                    tree,
                    hf_rtps_encapsulation_extended_compression_options,
                    tvb,
                    offset,
                    4,
                    ENC_BIG_ENDIAN);
            offset += 4;
        }
        /* Get the compressed size. Padding bytes are the padding at the end of the compressed data */
        compressed_size = size - (offset - initial_offset) - padding_bytes;
    }

    /* Only decompress if it is compressed with ZLIB */
    if (uncompress_if_compressed && (compression_option == RTI_OSAPI_COMPRESSION_CLASS_ID_ZLIB)) {
        gboolean tried_to_uncompress = FALSE;
        proto_item *uncompressed_data_item = NULL;

        /* Try to uncompress the data */
        uncompressed_tvb = rtps_util_get_uncompressed_tvb_zlib(
            tvb,
            offset,
            compressed_size,
            &tried_to_uncompress);
            /* The uncompressed data size must be the same as it is in the "Uncompressed Length" field */
            uncompressed_ok = (uncompressed_tvb != NULL
            && (uncompressed_size == (guint32)tvb_reported_length(uncompressed_tvb)));

        /* If uncompression went well we have a new tvb that holds the uncompressed data */
        if (tried_to_uncompress) {
            tvbuff_t *child_tvb = NULL;
            gint child_size = 0;
            gint child_offset = 0;

            /* If the tvb is not uncompressed we add use the ovb, offset and size
             * of the original tvb */
            if (uncompressed_tvb != NULL) {
                child_tvb = uncompressed_tvb;
                child_size = -1;
                child_offset = 0;
            } else {
                child_tvb = tvb;
                child_size = compressed_size;
                child_offset = offset;
            }
            /* Uncompressed sample hangs from a different subtree */
            *compressed_data_tree_out = proto_tree_add_subtree(
                tree,
                child_tvb,
                child_offset,
                child_size,
                ett_rtps_decompressed_serialized_data,
                &uncompressed_data_item,
                "[Decompressed data]");
            /* If we tried to decompress we need to add hf_rtps_uncompression_ok set to true or false*/
            if (!(uncompressed_ok)) {
                expert_add_info_format(
                    pinfo,
                    uncompressed_data_item,
                    &ei_rtps_uncompression_error,
                    "Error: unable to uncompress payload");
            }
        }
    }

    /* Set the optional output parameters */
    if (encapsulation_id_out != NULL) {
        *encapsulation_id_out = encapsulation_id;
    }
    if (compression_option_out != NULL) {
        *compression_option_out = compression_option;
    }
    if (padding_bytes_out != NULL) {
        *padding_bytes_out = padding_bytes;
    }
    if (extended_compression_options_out != NULL) {
        *extended_compression_options_out = extended_compression_options;
    }
    if (extended_header_bits_out != NULL) {
        *extended_header_bits_out = extended_header_bits;
    }
    if (is_compressed_out != NULL) {
        *is_compressed_out = is_compressed;
    }
    if (uncompressed_ok_out != NULL) {
        *uncompressed_ok_out = uncompressed_ok;
    }
    if (uncompressed_tvb_out != NULL) {
        *uncompressed_tvb_out = uncompressed_tvb;
    }
    return offset;
}



/* *********************************************************************** */
/* * Serialized data dissector                                           * */
/* *********************************************************************** */
/* Note: the encapsulation header is ALWAYS big endian, then the encapsulation
 * type specified the type of endianness of the payload.
 *
 *  Fragmentation : Options only appear on first fragment
 * Serieaized data might be compressed or uncompressed. Depending on that the
 * header contains more elements. This is indicated in the encapsulation
 * options where:
 *
 *  X = Unused options bits
 *  C = Compression bits
 *  P = Padding bits
 *
 * 0...2...........8...............16..............24..............32
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |   representation_identifier   |X X X X X X X X X X X|C C C P P|
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * ~                                                               ~
 * ~   ... Bytes of data representation using a format that ...    ~
 * ~  ... depends on the RepresentationIdentifier and options ...  ~
 * ~                                                               ~
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 * If compressed:
 *
 *  0...2...........8...............16..............24..............32
 *  + -+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  | representation_identifier | X X X X X X X X X X X | C C C P P |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  ~                    Uncompressed Length                        ~
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  ~                 *Extended Compression Options                 ~
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  ~                 Compressed User Data ...                      ~
 *  ~                                                               ~
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 *  C = 0b111 would be extended compression options which would come in as an
 *      additional header before the payload.
 *  C = 0b000 to indicate no compression
 *
 *  *This options field would be used for future enhancements.For example,
 *  could be used to define a custom compressor plugin for matching purposes.
 *
 */
static void dissect_serialized_data(proto_tree *tree, packet_info *pinfo, tvbuff_t *tvb, gint offset,
                        int  size, const char *label, guint16 vendor_id, gboolean is_discovery_data,
                        endpoint_guid * guid, gint32 frag_number /* -1 if no fragmentation */) {
  proto_item *ti;
  proto_tree *rtps_parameter_sequence_tree;
  guint16 encapsulation_id;
  gboolean try_dissection_from_type_object = FALSE;
  guint encapsulation_encoding = ENC_BIG_ENDIAN;
  rtps_dissector_data * data = wmem_new(wmem_packet_scope(), rtps_dissector_data);
  tvbuff_t *data_holder_tvb = tvb;
  tvbuff_t *compressed_tvb = NULL;
  proto_tree *dissected_data_holdeer_tree = NULL;
  gboolean is_compressed = FALSE;
  gboolean uncompressed_ok = FALSE;
  proto_tree *compressed_subtree = NULL;

  data->info_displayed = FALSE;
  data->encapsulation_id = 0;
  data->position_in_batch = -1;
  /* Creates the sub-tree */
  rtps_parameter_sequence_tree = proto_tree_add_subtree(tree, tvb, offset, size,
          ett_rtps_serialized_data, &ti, label);

  /* We store thisa value for using later */
  dissected_data_holdeer_tree = rtps_parameter_sequence_tree;

  if (frag_number > 1) {
    /* if the data is a fragment and not the first fragment, simply dissect the
       content as raw bytes */
    proto_tree_add_item(rtps_parameter_sequence_tree, hf_rtps_issue_data, tvb,
            offset, size, ENC_NA);
  } else {
    /* Dissects the encapsulation header options and uncompress the tvb if it is
     * compressed and can be uncompressed */
    offset = rtps_prepare_encapsulated_data(
        rtps_parameter_sequence_tree,
        pinfo,
        tvb,
        offset,
        size,
        TRUE,
        &encapsulation_id,
        NULL,
        NULL,
        NULL,
        NULL,
        &is_compressed,
        &uncompressed_ok,
        &compressed_tvb,
        &compressed_subtree);
    data->encapsulation_id = encapsulation_id;
    if (is_compressed && uncompressed_ok) {
        data_holder_tvb = compressed_tvb;
        offset = 0;
        dissected_data_holdeer_tree = compressed_subtree;
    }

    /* Sets the correct values for encapsulation_encoding */
    encapsulation_encoding = get_encapsulation_endianness(encapsulation_id);

    if (encapsulation_id == ENCAPSULATION_CDR_LE ||
        encapsulation_id == ENCAPSULATION_CDR_BE ||
        encapsulation_id == ENCAPSULATION_CDR2_LE ||
        encapsulation_id == ENCAPSULATION_CDR2_BE ||
        encapsulation_id == ENCAPSULATION_PL_CDR_LE ||
        encapsulation_id == ENCAPSULATION_PL_CDR_BE) {
      try_dissection_from_type_object = TRUE;
    }

    /* In case it is compressed only try to dissect the type oject if it is correctly uncompressed */
    try_dissection_from_type_object = try_dissection_from_type_object
        && ((is_compressed == uncompressed_ok));

    /* At this point:
     * - uncompressed_tvb contains the uncompressed tvb or the packet tvb
     * - compressed_data_tree points to the tree of the uncompressed data
     *       or the rtps_parameter_sequence_tree.
     * - offset points to 0 of the uncompressed tvb or the offseet of the packet
     *       tvb if it is not decompressed.
     * Only try to dissect the user data if it is not compressed or it is compressed and correctly uncompressed */
    if (is_compressed == uncompressed_ok) {
        if (rtps_util_topic_info_add_column_info_and_try_dissector(dissected_data_holdeer_tree,
                pinfo, data_holder_tvb, offset, guid, data, encapsulation_encoding,
                get_encapsulation_version(encapsulation_id), try_dissection_from_type_object)) {
            return;
        }
        /* The payload */
        size -= 4;
        switch (encapsulation_id) {
            /* CDR_LE and CDR_BE data should be dissected like this if it is a fragment or
               if it is not */
        case ENCAPSULATION_CDR_LE:
        case ENCAPSULATION_CDR_BE:
            proto_tree_add_item(dissected_data_holdeer_tree, hf_rtps_issue_data, data_holder_tvb,
                offset, size, ENC_NA);
            break;

        case ENCAPSULATION_PL_CDR_LE:
        case ENCAPSULATION_PL_CDR_BE:
            if (is_discovery_data) {
                dissect_parameter_sequence(dissected_data_holdeer_tree, pinfo, data_holder_tvb, offset,
                    encapsulation_encoding, size, "serializedData", 0x0200, NULL, vendor_id, FALSE, NULL);
            }
            else if (frag_number != NOT_A_FRAGMENT) {
                /* fragments should be dissected as raw bytes (not parametrized) */
                proto_tree_add_item(dissected_data_holdeer_tree, hf_rtps_issue_data, tvb,
                    offset, size, ENC_NA);
                break;
            }
            else {
                /* Instead of showing a warning like before, we now dissect the data as
                 * (id - length - value) members */
                dissect_parametrized_serialized_data(dissected_data_holdeer_tree,
                    tvb, offset, size, encapsulation_encoding);
            }
            break;

        default:
            proto_tree_add_item(dissected_data_holdeer_tree, hf_rtps_data_serialize_data, tvb,
                offset, size, ENC_NA);
        }
    } else {
        /* If uncompression fails we still need toadd the topic name to the column */
        rtps_util_topic_info_add_column_info(pinfo, guid, data);
    }
  }
}

/* *********************************************************************** */
/* *                            A P P_ A C K                             * */
/* *********************************************************************** */
static void dissect_APP_ACK(tvbuff_t *tvb,
  packet_info *pinfo,
  gint offset,
  guint8 flags,
  const guint encoding,
  int octets_to_next_header,
  proto_tree *tree,
  proto_item *item,
  endpoint_guid * guid)
  {
  /*
  * 0...2...........7...............15.............23...............31
  * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  * |   APP_ACK     |X|X|X|X|X|X|X|E|      octetsToNextHeader       |
  * +---------------+---------------+---------------+---------------+
  * | EntityId readerEntityId                                       |
  * +---------------+---------------+---------------+---------------+
  * | EntityId writerEntityId                                       |
  * +---------------+---------------+---------------+---------------+
  * + unsigned long virtualWriterCount                              +
  * +---------------+---------------+---------------+---------------+
  * | GuidPrefix  virtualWriterGuidPrefix                           |
  * +---------------+---------------+---------------+---------------+
  * EntityId virtualWriterObjectId
  * unsigned short intervalCount  | unsigned short bytesToNextVirtualWriter
  *
  * SequenceNumber intervalFirstSn
  * SequenceNumber intervalLastSn
  * unsigned short intervalFlags  | unsigned short payloadLength
  *
  * (after last interval) unsigned long virtualWriterEpoch
  *
  */
  gint original_offset; /* Offset to the readerEntityId */
  gint32 virtual_writer_count;
  guint32 wid;                  /* Writer EntityID */
  proto_item *octet_item;
  proto_tree_add_bitmask_value(tree, tvb, offset + 1, hf_rtps_sm_flags, ett_rtps_flags, APP_ACK_FLAGS, flags);

  octet_item = proto_tree_add_item(tree, hf_rtps_sm_octets_to_next_header, tvb,
      offset + 2, 2, encoding);

  if (octets_to_next_header < 56) {
    expert_add_info_format(pinfo, octet_item, &ei_rtps_sm_octets_to_next_header_error, "(Error: should be >= %u)", 56);
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
    &wid);
  offset += 4;
  guid->entity_id = wid;
  rtps_util_topic_info_add_tree(tree, tvb, offset, guid);

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

  /* virtualWriterCount */
  proto_tree_add_item_ret_int(tree, hf_rtps_param_app_ack_virtual_writer_count, tvb, offset, 4, encoding, &virtual_writer_count);
  offset += 4;


  {
    /* Deserialize Virtual Writers */
    proto_tree *sil_tree_writer_list;

    gint32 current_writer_index;
    gint32 current_interval_count;
    /* guint16 interval_flags = 0; */
    /* guint32 current_virtual_guid_index = 0;*/

    /** Writer list **/
    sil_tree_writer_list = proto_tree_add_subtree_format(tree, tvb, offset, -1,
           ett_rtps_app_ack_virtual_writer_list, NULL, "Virtual Writer List");

    current_writer_index = 0;

    while (current_writer_index < virtual_writer_count) {
      proto_tree *sil_tree_writer;
      proto_tree *sil_tree_interval_list;
      gint32 interval_count;

      sil_tree_writer = proto_tree_add_subtree_format(sil_tree_writer_list, tvb, offset, -1,
           ett_rtps_app_ack_virtual_writer, NULL, "virtualWriter[%d]", current_writer_index);

      /* Virtual Writer Guid */
#if 0
      rtps_util_add_generic_guid(sil_tree_writer,
      tvb,
      offset,
      "virtualGUID",
      buffer,
      MAX_GUID_SIZE);
#endif
      offset += 16;


      /* Interval count */
      proto_tree_add_item_ret_int(sil_tree_writer, hf_rtps_param_app_ack_interval_count,
        tvb, offset, 2, encoding, &interval_count);
      offset += 2;

      /* bytes to next virtual writer */
      proto_tree_add_item(sil_tree_writer, hf_rtps_param_app_ack_octets_to_next_virtual_writer,
        tvb, offset, 2, encoding);
      offset += 2;

      /* Interval list */
      sil_tree_interval_list = proto_tree_add_subtree_format(sil_tree_writer, tvb, offset, -1,
           ett_rtps_app_ack_virtual_writer_interval_list, NULL, "Interval List");

      current_interval_count = 0;
      while (current_interval_count < interval_count) {
        proto_tree *sil_tree_interval;
        gint32 interval_payload_length;

        sil_tree_interval = proto_tree_add_subtree_format(sil_tree_interval_list, tvb, offset, -1,
           ett_rtps_app_ack_virtual_writer_interval, NULL, "Interval[%d]", current_interval_count);

        /* firstVirtualSN */
        rtps_util_add_seq_number(sil_tree_interval,
          tvb,
          offset,
          encoding,
          "firstVirtualSN");
        offset += 8;

        /* lastVirtualSN */
        rtps_util_add_seq_number(sil_tree_interval,
          tvb,
          offset,
          encoding,
          "lastVirtualSN");
        offset += 8;

        /* interval flags */
        proto_tree_add_item(sil_tree_interval, hf_rtps_param_app_ack_interval_flags,
          tvb, offset, 2, encoding);
        offset += 2;

        /* interval payload length */
        proto_tree_add_item_ret_int(sil_tree_interval, hf_rtps_param_app_ack_interval_payload_length,
          tvb, offset, 2, encoding, &interval_payload_length);
        offset += 2;

        if (interval_payload_length > 0) {
          proto_tree_add_item(sil_tree_interval, hf_rtps_serialized_data, tvb, offset,
                  interval_payload_length, ENC_NA);
          offset += ((interval_payload_length + 3) & 0xfffffffc);
        }

        ++current_interval_count;

      } /* interval list */

      /* Count */
      proto_tree_add_item(tree, hf_rtps_param_app_ack_count, tvb, offset, 4, encoding);
      offset += 4;

      current_writer_index++;

    } /* virtual_writer_count */
  }


  if (offset < original_offset + octets_to_next_header)
  {
    /* In this case there must be something wrong in the bitmap: there
    * are some extra bytes that we don't know how to decode
    */
    expert_add_info_format(pinfo, item, &ei_rtps_extra_bytes, "Don't know how to decode those extra bytes: %d", octets_to_next_header - offset);
  }
  else if (offset > original_offset + octets_to_next_header)
  {
    /* Decoding the bitmap went over the end of this submessage.
    * Enter an item in the protocol tree that spans over the entire
    * submessage.
    */
    expert_add_info(pinfo, item, &ei_rtps_missing_bytes);
  }
}

/* *********************************************************************** */
/* *                                 P A D                               * */
/* *********************************************************************** */
static void dissect_PAD(tvbuff_t *tvb,
                packet_info *pinfo,
                gint offset,
                guint8 flags,
                const guint encoding,
                int octets_to_next_header,
                proto_tree *tree) {
  /* 0...2...........7...............15.............23...............31
   * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   * |   PAD         |X|X|X|X|X|X|X|E|      octetsToNextHeader       |
   * +---------------+---------------+---------------+---------------+
   */
  proto_item *item;

  proto_tree_add_bitmask_value(tree, tvb, offset + 1, hf_rtps_sm_flags, ett_rtps_flags, PAD_FLAGS, flags);

  item = proto_tree_add_item(tree,
                          hf_rtps_sm_octets_to_next_header,
                          tvb,
                          offset + 2,
                          2,
                          encoding);
  if (octets_to_next_header != 0) {
    expert_add_info(pinfo, item, &ei_rtps_sm_octets_to_next_header_not_zero);
  }
}





/* *********************************************************************** */
/* *                               D A T A                               * */
/* *********************************************************************** */
static void dissect_DATA_v1(tvbuff_t *tvb, packet_info *pinfo, gint offset, guint8 flags,
                const guint encoding, int octets_to_next_header, proto_tree *tree) {
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
  gboolean is_builtin_entity = FALSE;    /* true=entityId.entityKind = built-in */
  gint old_offset = offset;
  guint32 wid;                  /* Writer EntityID */
  proto_item *octet_item;

  proto_tree_add_bitmask_value(tree, tvb, offset + 1, hf_rtps_sm_flags, ett_rtps_flags, DATA_FLAGSv1, flags);

  octet_item = proto_tree_add_item(tree, hf_rtps_sm_octets_to_next_header, tvb,
                        offset + 2, 2, encoding);

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
   * ENTITYID_BUILTIN_PARTICIPANT_WRITER        |    1   | p+
   * ENTITYID_BUILTIN_PARTICIPANT_WRITER        |    0   | p-   (*)
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
  } else if (wid == ENTITYID_BUILTIN_PARTICIPANT_WRITER && (flags & FLAG_DATA_A) != 0) {
      col_append_str(pinfo->cinfo, COL_INFO, SM_EXTRA_PPLUS);
  } else if (wid == ENTITYID_BUILTIN_PARTICIPANT_WRITER && (flags & FLAG_DATA_A) == 0) {
      col_append_str(pinfo->cinfo, COL_INFO, SM_EXTRA_PMINUS);
  } else if (wid == ENTITYID_BUILTIN_TOPIC_WRITER && (flags & FLAG_DATA_A) != 0) {
      col_append_str(pinfo->cinfo, COL_INFO, SM_EXTRA_TPLUS);
  } else if (wid == ENTITYID_BUILTIN_TOPIC_WRITER && (flags & FLAG_DATA_A) == 0) {
      col_append_str(pinfo->cinfo, COL_INFO, SM_EXTRA_TMINUS);
  }

  /* If flag H is defined, read the HostId and AppId fields */
  if ((flags & FLAG_DATA_H) != 0) {
    rtps_util_add_guid_prefix_v1(tree, tvb, offset,
                        hf_rtps_sm_guid_prefix_v1, hf_rtps_sm_host_id, hf_rtps_sm_app_id,
                        hf_rtps_sm_instance_id_v1, hf_rtps_sm_app_kind,
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
  rtps_util_add_seq_number(tree, tvb, offset, encoding, "writerSeqNumber");
  offset += 8;

  /* InlineQos */
  if ((flags & FLAG_DATA_Q) != 0) {
    gboolean is_inline_qos = TRUE;
    offset = dissect_parameter_sequence(tree, pinfo, tvb, offset,
                        encoding, octets_to_next_header, "inlineQos",
                        0x0102, NULL, 0, is_inline_qos, NULL);
  }

  /* SerializedData */
  if ((flags & FLAG_DATA_D) != 0) {
    if (is_builtin_entity) {
      dissect_parameter_sequence(tree, pinfo, tvb, offset,
                        encoding, octets_to_next_header, "serializedData",
                        0x0102, NULL, 0, FALSE, NULL);
    } else {
      proto_tree_add_item(tree, hf_rtps_issue_data, tvb, offset,
                        octets_to_next_header - (offset - old_offset) + 4,
                        ENC_NA);
    }
  }
}

static void dissect_DATA_v2(tvbuff_t *tvb, packet_info *pinfo, gint offset, guint8 flags,
                            const guint encoding, int octets_to_next_header, proto_tree *tree,
                            guint16 vendor_id, endpoint_guid *guid) {
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
  proto_item *octet_item;
  gboolean from_builtin_writer;

  proto_tree_add_bitmask_value(tree, tvb, offset + 1, hf_rtps_sm_flags, ett_rtps_flags, DATA_FLAGSv2, flags);

  octet_item = proto_tree_add_item(tree, hf_rtps_sm_octets_to_next_header, tvb,
                        offset + 2, 2, encoding);

  /* Calculates the minimum length for this submessage */
  min_len = 20;
  if ((flags & FLAG_DATA_Q_v2) != 0) min_len += 4;
  if ((flags & FLAG_DATA_D_v2) != 0) min_len += 4;
  if ((flags & FLAG_DATA_H) != 0) min_len += 12;

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
                        hf_rtps_sm_wrentity_id_kind, ett_rtps_wrentity, "writerEntityId", &wid);
  offset += 4;
  guid->entity_id = wid;
  guid->fields_present |= GUID_HAS_ENTITY_ID;
  rtps_util_topic_info_add_tree(tree, tvb, offset, guid);

  /* Sequence number */
  rtps_util_add_seq_number(tree, tvb, offset, encoding, "writerSeqNumber");
  offset += 8;

  /* If flag H is defined, read the GUID Prefix */
  if ((flags & FLAG_DATA_H) != 0) {
    rtps_util_add_guid_prefix_v2(tree, tvb, offset, hf_rtps_sm_guid_prefix, hf_rtps_sm_host_id,
                        hf_rtps_sm_app_id, hf_rtps_sm_instance_id, 0);

    offset += 12;
  } else {
    /* Flag H not set, use hostId, appId from the packet header */
  }

  /* Complete the GUID by reading the Object ID */
  rtps_util_add_entity_id(tree, tvb, offset, hf_rtps_sm_entity_id, hf_rtps_sm_entity_id_key,
                        hf_rtps_sm_entity_id_kind, ett_rtps_entity, "keyHashSuffix", NULL);
  offset += 4;

  if ((flags & FLAG_DATA_I) != 0) {
    proto_tree_add_item(tree, hf_rtps_data_status_info, tvb, offset, 4, encoding);
    offset += 4;
  }

  /* InlineQos */
  if ((flags & FLAG_DATA_Q_v2) != 0) {
    gboolean is_inline_qos = TRUE;
    offset = dissect_parameter_sequence(tree, pinfo, tvb, offset, encoding,
                        octets_to_next_header - (offset - old_offset) + 4,
                        "inlineQos", 0x0200, NULL, vendor_id, is_inline_qos, NULL);
  }

  /* SerializedData */
  if ((flags & FLAG_DATA_D_v2) != 0) {
    from_builtin_writer =
        (((wid & 0xc2) == 0xc2) || ((wid & 0xc3) == 0xc3)) ? TRUE : FALSE;
    dissect_serialized_data(tree, pinfo, tvb, offset,
                        octets_to_next_header - (offset - old_offset) + 4,
                        "serializedData", vendor_id, from_builtin_writer, guid, NOT_A_FRAGMENT);
  }
  append_status_info(pinfo, wid, status_info);
}

static void dissect_DATA_FRAG(tvbuff_t *tvb, packet_info *pinfo, gint offset, guint8 flags,
                const guint encoding, int octets_to_next_header, proto_tree *tree,
                guint16 vendor_id, endpoint_guid *guid) {
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
  guint32 frag_number = 0;
  proto_item *octet_item;
  guint32 wid;
  gboolean from_builtin_writer;

  proto_tree_add_bitmask_value(tree, tvb, offset + 1, hf_rtps_sm_flags, ett_rtps_flags, DATA_FRAG_FLAGS, flags);

  octet_item = proto_tree_add_item(tree, hf_rtps_sm_octets_to_next_header, tvb,
                        offset + 2, 2, encoding);

  /* Calculates the minimum length for this submessage */
  min_len = 32;
  if ((flags & FLAG_DATA_FRAG_Q) != 0) min_len += 4;
  if ((flags & FLAG_DATA_FRAG_H) != 0) min_len += 12;

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
                        hf_rtps_sm_wrentity_id_kind, ett_rtps_wrentity, "writerEntityId", &wid);
  offset += 4;
  guid->entity_id = wid;
  guid->fields_present |= GUID_HAS_ENTITY_ID;
  rtps_util_topic_info_add_tree(tree, tvb, offset, guid);

  /* Sequence number */
  rtps_util_add_seq_number(tree, tvb, offset, encoding, "writerSeqNumber");
  offset += 8;

  /* If flag H is defined, read the GUID Prefix */
  if ((flags & FLAG_DATA_H) != 0) {
    rtps_util_add_guid_prefix_v2(tree, tvb, offset, hf_rtps_sm_guid_prefix,
                    hf_rtps_sm_host_id, hf_rtps_sm_app_id, hf_rtps_sm_instance_id, 0);
    offset += 12;
  } else {
    /* Flag H not set, use hostId, appId from the packet header */
  }

  /* Complete the GUID by reading the Object ID */
  rtps_util_add_entity_id(tree, tvb, offset, hf_rtps_sm_entity_id, hf_rtps_sm_entity_id_key,
                        hf_rtps_sm_entity_id_kind, ett_rtps_entity, "keyHashSuffix", NULL);
  offset += 4;


  /* Fragment number */
  proto_tree_add_item_ret_uint(tree, hf_rtps_data_frag_number, tvb, offset, 4, encoding, &frag_number);
  offset += 4;

  /* Fragments in submessage */
  proto_tree_add_item(tree, hf_rtps_data_frag_num_fragments, tvb, offset, 2, encoding);
  offset += 2;

  /* Fragment size */
  proto_tree_add_item(tree, hf_rtps_data_frag_size, tvb, offset, 2, encoding);
  offset += 2;

  /* sampleSize */
  proto_tree_add_item(tree, hf_rtps_data_frag_sample_size, tvb, offset, 4, encoding);
  offset += 4;

  /* InlineQos */
  if ((flags & FLAG_DATA_Q_v2) != 0) {
    gboolean is_inline_qos = TRUE;
    offset = dissect_parameter_sequence(tree, pinfo, tvb, offset, encoding,
                        octets_to_next_header - (offset - old_offset) + 4,
                        "inlineQos", 0x0200, NULL, vendor_id, is_inline_qos, NULL);
  }

  /* SerializedData */
  if ((flags & FLAG_DATA_D_v2) != 0) {
    from_builtin_writer =
        (((wid & 0xc2) == 0xc2) || ((wid & 0xc3) == 0xc3)) ? TRUE : FALSE;
    dissect_serialized_data(tree, pinfo, tvb, offset,
                        octets_to_next_header - (offset - old_offset) + 4,
                        "serializedData", vendor_id, from_builtin_writer, NULL, (gint32)frag_number);
  }
}


/* *********************************************************************** */
/* *                        N O K E Y _ D A T A                          * */
/* *********************************************************************** */
static void dissect_NOKEY_DATA(tvbuff_t *tvb, packet_info *pinfo, gint offset, guint8 flags,
                const guint encoding, int octets_to_next_header, proto_tree *tree,
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
  guint32 wid;                  /* Writer EntityID */
  gboolean from_builtin_writer;
  gint old_offset = offset;
  proto_item *octet_item;

  proto_tree_add_bitmask_value(tree, tvb, offset + 1, hf_rtps_sm_flags, ett_rtps_flags, NOKEY_DATA_FLAGS, flags);

  octet_item = proto_tree_add_item(tree, hf_rtps_sm_octets_to_next_header, tvb,
                        offset + 2, 2, encoding);

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
                        hf_rtps_sm_wrentity_id_kind, ett_rtps_wrentity, "writerEntityId", &wid);
  offset += 4;

  /* Sequence number */
  rtps_util_add_seq_number(tree, tvb, offset, encoding, "writerSeqNumber");
  offset += 8;

  /* Parameters */
  if ((flags & FLAG_NOKEY_DATA_Q) != 0) {
    gboolean is_inline_qos = TRUE;
    offset = dissect_parameter_sequence(tree, pinfo, tvb, offset,
                        encoding, octets_to_next_header, "inlineQos",
                        version, NULL, vendor_id, is_inline_qos, NULL);

  }

  /* Issue Data */
  if ((version < 0x0200) && (flags & FLAG_NOKEY_DATA_D) == 0) {
    proto_tree_add_item(tree, hf_rtps_issue_data, tvb, offset,
                         octets_to_next_header - (offset - old_offset) + 4,
                        ENC_NA);
  }

  if ((version >= 0x0200) && (flags & FLAG_DATA_D_v2) != 0) {
    from_builtin_writer =
        (((wid & 0xc2) == 0xc2) || ((wid & 0xc3) == 0xc3)) ? TRUE : FALSE;
    dissect_serialized_data(tree, pinfo, tvb, offset,
                        octets_to_next_header - (offset - old_offset) + 4,
                        "serializedData", vendor_id, from_builtin_writer, NULL, NOT_A_FRAGMENT);
  }

}

/* *********************************************************************** */
/* *                    N O K E Y _ D A T A _ F R A G                    * */
/* *********************************************************************** */
static void dissect_NOKEY_DATA_FRAG(tvbuff_t *tvb, packet_info *pinfo, gint offset,
                guint8 flags, const guint encoding, int octets_to_next_header, proto_tree *tree,
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
  guint32 wid;                  /* Writer EntityID */
  gboolean from_builtin_writer;
  gint old_offset = offset;
  guint32 frag_number = 0;
  proto_item *octet_item;
  proto_tree_add_bitmask_value(tree, tvb, offset + 1, hf_rtps_sm_flags, ett_rtps_flags, NOKEY_DATA_FRAG_FLAGS, flags);

  octet_item = proto_tree_add_item(tree, hf_rtps_sm_octets_to_next_header, tvb,
                        offset + 2, 2, encoding);

  /* Calculates the minimum length for this submessage */
  min_len = 28;
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
                        hf_rtps_sm_wrentity_id_kind, ett_rtps_wrentity, "writerEntityId", &wid);
  offset += 4;

  /* Sequence number */
  rtps_util_add_seq_number(tree, tvb, offset, encoding, "writerSeqNumber");
  offset += 8;

  /* Fragment number */
  proto_tree_add_item_ret_uint(tree, hf_rtps_nokey_data_frag_number, tvb,
                        offset, 4, encoding, &frag_number);
  offset += 4;

  /* Fragments in submessage */
  proto_tree_add_item(tree, hf_rtps_nokey_data_frag_num_fragments, tvb,
                        offset, 2, encoding);
  offset += 2;

  /* Fragment size */
  proto_tree_add_item(tree, hf_rtps_nokey_data_frag_size, tvb,
                        offset, 2, encoding);
  offset += 2;

  /* InlineQos */
  if ((flags & FLAG_DATA_Q_v2) != 0) {
    gboolean is_inline_qos = TRUE;
    offset = dissect_parameter_sequence(tree, pinfo, tvb, offset, encoding,
                        octets_to_next_header - (offset - old_offset) + 4,
                        "inlineQos", 0x0200, NULL, vendor_id, is_inline_qos, NULL);
  }

  /* SerializedData */
  if ((flags & FLAG_DATA_D_v2) != 0) {
    from_builtin_writer =
      (((wid & 0xc2) == 0xc2) || ((wid & 0xc3) == 0xc3)) ? TRUE : FALSE;
    dissect_serialized_data(tree, pinfo, tvb,offset,
                        octets_to_next_header - (offset - old_offset) + 4,
                        "serializedData", vendor_id, from_builtin_writer, NULL, (gint32)frag_number);
  }
}


/* *********************************************************************** */
/* *                            A C K N A C K                            * */
/* *********************************************************************** */
static void dissect_ACKNACK(tvbuff_t *tvb, packet_info *pinfo, gint offset, guint8 flags,
                const guint encoding, int octets_to_next_header, proto_tree *tree,
                proto_item *item, endpoint_guid *guid) {
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
  proto_item *octet_item;
  guint32 wid;
  proto_tree_add_bitmask_value(tree, tvb, offset + 1, hf_rtps_sm_flags, ett_rtps_flags, ACKNACK_FLAGS, flags);

  octet_item = proto_tree_add_item(tree, hf_rtps_sm_octets_to_next_header, tvb, offset + 2, 2, encoding);

  if (octets_to_next_header < 20) {
    expert_add_info_format(pinfo, octet_item, &ei_rtps_sm_octets_to_next_header_error, "(Error: should be >= 20)");
    return;
  }

  offset += 4;
  original_offset = offset;

  /* readerEntityId */
  rtps_util_add_entity_id(tree, tvb, offset, hf_rtps_sm_rdentity_id, hf_rtps_sm_rdentity_id_key,
                        hf_rtps_sm_rdentity_id_kind, ett_rtps_rdentity, "readerEntityId", NULL);
  offset += 4;

  /* writerEntityId */
  rtps_util_add_entity_id(tree, tvb, offset, hf_rtps_sm_wrentity_id, hf_rtps_sm_wrentity_id_key,
                        hf_rtps_sm_wrentity_id_kind, ett_rtps_wrentity, "writerEntityId", &wid);
  offset += 4;
  guid->entity_id = wid;
  guid->fields_present |= GUID_HAS_ENTITY_ID;
  rtps_util_topic_info_add_tree(tree, tvb, offset, guid);

  /* Bitmap */
  offset = rtps_util_add_bitmap(tree, tvb, offset, encoding, "readerSNState", TRUE);

  /* RTPS 1.0 didn't have count: make sure we don't decode it wrong
   * in this case
   */
  if (offset + 4 == original_offset + octets_to_next_header) {
    /* Count is present */
    proto_tree_add_item(tree, hf_rtps_acknack_count, tvb, offset, 4, encoding);
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
                              const guint encoding, int octets_to_next_header, proto_tree *tree) {
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
  proto_item *octet_item;

  proto_tree_add_bitmask_value(tree, tvb, offset + 1, hf_rtps_sm_flags, ett_rtps_flags, NACK_FRAG_FLAGS, flags);

  octet_item = proto_tree_add_item(tree, hf_rtps_sm_octets_to_next_header, tvb,
                        offset + 2, 2, encoding);

  if (octets_to_next_header < 24) {
    expert_add_info_format(pinfo, octet_item, &ei_rtps_sm_octets_to_next_header_error, "(Error: should be >= 24)");
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
  rtps_util_add_seq_number(tree, tvb, offset, encoding, "writerSN");
  offset += 8;

  /* FragmentNumberSet */
  offset = rtps_util_add_fragment_number_set(tree, pinfo, tvb, offset, encoding,
                        "fragmentNumberState", octets_to_next_header - 20);

  if (offset == -1) {
    return;
  }
  /* Count */
  proto_tree_add_item(tree, hf_rtps_nack_frag_count, tvb, offset, 4, encoding);
}

/* *********************************************************************** */
/* *                           H E A R T B E A T                         * */
/* *********************************************************************** */
static void dissect_HEARTBEAT(tvbuff_t *tvb, packet_info *pinfo, gint offset, guint8 flags,
                const guint encoding, int octets_to_next_header, proto_tree *tree,
                guint16 version, endpoint_guid *guid) {
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
  proto_item *octet_item;
  guint32 wid;
  proto_tree_add_bitmask_value(tree, tvb, offset + 1, hf_rtps_sm_flags, ett_rtps_flags, HEARTBEAT_FLAGS, flags);

  octet_item = proto_tree_add_item(tree,
                        hf_rtps_sm_octets_to_next_header,
                        tvb,
                        offset + 2,
                        2,
                        encoding);

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
                        hf_rtps_sm_wrentity_id_kind, ett_rtps_wrentity, "writerEntityId", &wid);
  offset += 4;
  guid->entity_id = wid;
  guid->fields_present |= GUID_HAS_ENTITY_ID;
  rtps_util_topic_info_add_tree(tree, tvb, offset, guid);

  /* First available Sequence Number */
  rtps_util_add_seq_number(tree, tvb, offset, encoding, "firstAvailableSeqNumber");
  offset += 8;

  /* Last Sequence Number */
  rtps_util_add_seq_number(tree, tvb, offset, encoding, "lastSeqNumber");
  offset += 8;

  /* Counter: it was not present in RTPS 1.0 */
  if (version >= 0x0101) {
    proto_tree_add_item(tree, hf_rtps_heartbeat_count, tvb, offset, 4, encoding);
  }
}

/* *********************************************************************** */
/* *                 H E A R T B E A T _ B A T C H                       * */
/* *********************************************************************** */
static void dissect_HEARTBEAT_BATCH(tvbuff_t *tvb, packet_info *pinfo, gint offset,
                guint8 flags, const guint encoding, int octets_to_next_header,
                proto_tree *tree, endpoint_guid *guid) {
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
  proto_item *octet_item;
  guint32 wid;
  proto_tree_add_bitmask_value(tree, tvb, offset + 1, hf_rtps_sm_flags, ett_rtps_flags, HEARTBEAT_BATCH_FLAGS, flags);

  octet_item = proto_tree_add_item(tree, hf_rtps_sm_octets_to_next_header, tvb,
                        offset + 2, 2, encoding);

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
                        hf_rtps_sm_wrentity_id_kind, ett_rtps_wrentity, "writerEntityId", &wid);
  offset += 4;
  guid->entity_id = wid;
  guid->fields_present |= GUID_HAS_ENTITY_ID;
  rtps_util_topic_info_add_tree(tree, tvb, offset, guid);

  /* First available Batch Sequence Number */
  rtps_util_add_seq_number(tree, tvb, offset, encoding, "firstBatchSN");
  offset += 8;

  /* Last Batch Sequence Number */
  rtps_util_add_seq_number(tree, tvb, offset, encoding, "lastBatchSN");
  offset += 8;

  /* First available Sequence Number */
  rtps_util_add_seq_number(tree, tvb, offset, encoding, "firstSeqNumber");
  offset += 8;

  /* Last Sequence Number */
  rtps_util_add_seq_number(tree, tvb, offset, encoding, "lastSeqNumber");
  offset += 8;

  /* Counter */
  proto_tree_add_item(tree, hf_rtps_heartbeat_batch_count, tvb, offset, 4, encoding);
}

/* *********************************************************************** */
/* *                  H E A R T B E A T _ V I R T U A L                  * */
/* *********************************************************************** */

static void dissect_HEARTBEAT_VIRTUAL(tvbuff_t *tvb, packet_info *pinfo _U_, gint offset,
                guint8 flags, const guint encoding, int octets_to_next_header, proto_tree *tree,
                guint16 vendor_id _U_, endpoint_guid *guid) {

    /*
    * VIRTUAL_HB:
    *
    * 0...2...........7...............15.............23...............31
    * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    * | VIRTUAL_HB    |X|X|X|X|N|W|V|E| octetsToNextHeader            |
    * +---------------+---------------+---------------+---------------+
    * | EntityId readerId                                             |
    * +---------------+---------------+---------------+---------------+
    * | EntityId writerId                                             |
    * +---------------+---------------+---------------+---------------+
    * | Guid_t virtualGUID (V=0 & N=0)                                |
    * +                                                               +
    * |                                                               |
    * +                                                               +
    * |                                                               |
    * +                                                               +
    * |                                                               |
    * +---------------+---------------+---------------+---------------+
    * | unsigned long numWriters (W=1)                                |
    * +---------------+---------------+---------------+---------------+
    * |                                                               |
    * ~ WriterVirtualHBList writerVirtualHBList                       ~
    * |                                                               |
    * +---------------+---------------+---------------+---------------+
    * | unsigned long count                                           |
    * +---------------+---------------+---------------+---------------+

    * WRITER_VIRTUAL_HB:
    *
    * 0...2...........7...............15.............23...............31
    * +---------------+---------------+---------------+---------------+
    * | EntityId writerId (W=1)                                       |
    * +---------------+---------------+---------------+---------------+
    * | unsigned long numVirtualGUIDs (N=0)                           |
    * +---------------+---------------+---------------+---------------+
    * |                                                               |
    * ~ VirtualGUIDHBList virtualGUIDHBList                           ~
    * |                                                               |
    * +---------------+---------------+---------------+---------------+
    *
    * VIRTUAL_GUID_HB:
    *
    * 0...2...........7...............15.............23...............31
    * +---------------+---------------+---------------+---------------+
    * | Guid_t virtualGUID (V=1)                                      |
    * +                                                               +
    * |                                                               |
    * +                                                               +
    * |                                                               |
    * +                                                               +
    * |                                                               |
    * +---------------+---------------+---------------+---------------+
    * |                                                               |
    * + SequenceNumber firstVirtualSN                                 +
    * |                                                               |
    * +---------------+---------------+---------------+---------------+
    * |                                                               |
    * + SequenceNumber lastVirtualSN                                  +
    * |                                                               |
    * +---------------+---------------+---------------+---------------+
    * |                                                               |
    * + SequenceNumber firstRTPSSN                                    +
    * |                                                               |
    * +---------------+---------------+---------------+---------------+
    * |                                                               |
    * + SequenceNumber lastRTPSSN                                     +
    * |                                                               |
    * +---------------+---------------+---------------+---------------+
    */

    guint32 num_writers, num_virtual_guids, wid;
    gint writer_id_offset, virtual_guid_offset = 0, old_offset;
    proto_item *octet_item, *ti;

    proto_tree_add_bitmask_value(tree, tvb, offset + 1, hf_rtps_sm_flags, ett_rtps_flags, HEARTBEAT_VIRTUAL_FLAGS, flags);

    octet_item = proto_tree_add_item(tree, hf_rtps_sm_octets_to_next_header, tvb,
      offset + 2, 2, encoding);

    if (octets_to_next_header < 12) {
      expert_add_info_format(pinfo, octet_item, &ei_rtps_sm_octets_to_next_header_error, "(Error: should be >= %u)", 12);
      return;
    }
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
    writer_id_offset = offset;
    offset += 4;
    guid->entity_id = wid;
    guid->fields_present |= GUID_HAS_ENTITY_ID;
    rtps_util_topic_info_add_tree(tree, tvb, offset, guid);

    /* virtualGUID */
    if (!(flags & FLAG_VIRTUAL_HEARTBEAT_V) && !(flags & FLAG_VIRTUAL_HEARTBEAT_N)) {
      /*rtps_util_add_generic_guid(tree,
      tvb,
      offset,
      "virtualGUID",
      buffer,
      MAX_GUID_SIZE);*/
      virtual_guid_offset = offset;
      offset += 16;
    }

    /* num_writers */
    ti = proto_tree_add_item(tree, hf_rtps_virtual_heartbeat_num_writers, tvb,
        offset, 4, encoding);
    if (flags & FLAG_VIRTUAL_HEARTBEAT_W) {
      num_writers = tvb_get_guint32(tvb, offset, encoding);
      offset += 4;
    } else {
      proto_item_set_text(ti, "numWriters: 1");
      num_writers = 1;
    }

    {
      /* Deserialize Writers */
      proto_tree *sil_tree_writer_list;
      guint32 current_writer_index;

      /** Writer list **/
      sil_tree_writer_list = proto_tree_add_subtree_format(tree, tvb, offset, -1,
           ett_rtps_writer_heartbeat_virtual_list, NULL, "Writer List");

      current_writer_index = 0;

      while (current_writer_index < num_writers) {
        proto_tree *sil_tree_writer;
        sil_tree_writer = proto_tree_add_subtree_format(sil_tree_writer_list, tvb, offset, -1,
           ett_rtps_writer_heartbeat_virtual, NULL, "writer[%d]", current_writer_index);

        if (num_writers == 1) {
          old_offset = offset;
          offset = writer_id_offset;
        }

        rtps_util_add_entity_id(sil_tree_writer,
          tvb,
          offset,
          hf_rtps_sm_wrentity_id,
          hf_rtps_sm_wrentity_id_key,
          hf_rtps_sm_wrentity_id_kind,
          ett_rtps_wrentity,
          "writerEntityId",
          NULL);

        if (num_writers == 1) {
          offset = old_offset;
        } else {
          offset += 4;
        }

        if (!(flags & FLAG_VIRTUAL_HEARTBEAT_N)) {
          proto_tree_add_item(sil_tree_writer, hf_rtps_virtual_heartbeat_num_virtual_guids, tvb,
            offset, 4, encoding);
          num_virtual_guids = tvb_get_guint32(tvb, offset, encoding);
          offset += 4;
        } else {
          num_virtual_guids = 0;
        }

        /** Virtual GUID list **/
        if (num_virtual_guids != 0) {
          proto_tree *sil_tree_virtual_guid_list;
          guint32 current_virtual_guid_index;

          sil_tree_virtual_guid_list = proto_tree_add_subtree_format(sil_tree_writer, tvb, offset, -1,
           ett_rtps_virtual_guid_heartbeat_virtual_list, NULL, "Virtual GUID List");

          current_virtual_guid_index = 0;

          while (current_virtual_guid_index < num_virtual_guids) {
            proto_tree *sil_tree_virtual_guid;
            sil_tree_virtual_guid = proto_tree_add_subtree_format(sil_tree_virtual_guid_list, tvb, offset, -1,
                ett_rtps_virtual_guid_heartbeat_virtual, NULL, "virtualGUID[%d]", current_virtual_guid_index);

            if (!(flags & FLAG_VIRTUAL_HEARTBEAT_V)) {
              old_offset = offset;
              offset = virtual_guid_offset;
            }

            /*rtps_util_add_generic_guid_v2(sil_tree_virtual_guid,
            tvb,
            offset,
            "virtualGUID",
            buffer,
            MAX_GUID_SIZE);*/

            if (!(flags & FLAG_VIRTUAL_HEARTBEAT_V)) {
              offset = old_offset;
            } else {
              offset += 16;
            }

            /* firstVirtualSN */
            rtps_util_add_seq_number(sil_tree_virtual_guid,
              tvb,
              offset,
              encoding,
              "firstVirtualSN");
            offset += 8;

            /* lastVirtualSN */
            rtps_util_add_seq_number(sil_tree_virtual_guid,
              tvb,
              offset,
              encoding,
              "lastVirtualSN");
            offset += 8;

            /* firstRTPSSN */
            rtps_util_add_seq_number(sil_tree_virtual_guid,
              tvb,
              offset,
              encoding,
              "firstRTPSSN");
            offset += 8;

            /* lastRTPSSN */
            rtps_util_add_seq_number(sil_tree_virtual_guid,
              tvb,
              offset,
              encoding,
              "lastRTPSSN");
            offset += 8;

            current_virtual_guid_index++;
          }
        }

        current_writer_index++;
      }
    }

    /* Count */
    proto_tree_add_item(tree, hf_rtps_virtual_heartbeat_count, tvb, offset, 4, encoding);
  }


/* *********************************************************************** */
/* *                   H E A R T B E A T _ F R A G                       * */
/* *********************************************************************** */
static void dissect_HEARTBEAT_FRAG(tvbuff_t *tvb, packet_info *pinfo, gint offset, guint8 flags,
                const guint encoding, int octets_to_next_header, proto_tree *tree, endpoint_guid *guid) {
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
  proto_item *octet_item;
  guint32 wid;
  proto_tree_add_bitmask_value(tree, tvb, offset + 1, hf_rtps_sm_flags, ett_rtps_flags, HEARTBEAT_FRAG_FLAGS, flags);

  octet_item = proto_tree_add_item(tree, hf_rtps_sm_octets_to_next_header, tvb,
                        offset + 2, 2, encoding);

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
                        hf_rtps_sm_wrentity_id_kind, ett_rtps_wrentity, "writerEntityId", &wid);
  offset += 4;
  guid->entity_id = wid;
  guid->fields_present |= GUID_HAS_ENTITY_ID;
  rtps_util_topic_info_add_tree(tree, tvb, offset, guid);

  /* First available Sequence Number */
  rtps_util_add_seq_number(tree, tvb, offset, encoding, "writerSeqNumber");
  offset += 8;

  /* Fragment number */
  proto_tree_add_item(tree, hf_rtps_heartbeat_frag_number, tvb, offset, 4, encoding);
  offset += 4;

  /* Counter */
  proto_tree_add_item(tree, hf_rtps_heartbeat_frag_count, tvb, offset, 4, encoding);
}

/* *********************************************************************** */
/* *                     R T P S _ D A T A                               * */
/* *                           A N D                                     * */
/* *             R T P S _ D A T A _ S E S S I O N                       * */
/* *********************************************************************** */
static void dissect_RTPS_DATA(tvbuff_t *tvb, packet_info *pinfo, gint offset, guint8 flags,
                guint encoding, int octets_to_next_header, proto_tree *tree,
                guint16 vendor_id, gboolean is_session, endpoint_guid *guid) {
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
  gboolean from_builtin_writer;
  proto_item *octet_item;
  coherent_set_entity_info coherent_set_entity_info_object;

  proto_tree_add_bitmask_value(tree, tvb, offset + 1, hf_rtps_sm_flags, ett_rtps_flags, RTPS_DATA_FLAGS, flags);

  octet_item = proto_tree_add_item(tree, hf_rtps_sm_octets_to_next_header, tvb,
                        offset + 2, 2, encoding);

  /* Calculates the minimum length for this submessage */
  min_len = 20;
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

  offset += 4;

  /* extraFlags */
  proto_tree_add_item(tree, hf_rtps_extra_flags, tvb, offset, 2, ENC_BIG_ENDIAN);
  offset += 2;

  /* octetsToInlineQos */
  proto_tree_add_item(tree, hf_rtps_octets_to_inline_qos, tvb, offset, 2, encoding);
  offset += 2;

  /* readerEntityId */
  rtps_util_add_entity_id(tree, tvb, offset, hf_rtps_sm_rdentity_id, hf_rtps_sm_rdentity_id_key,
                        hf_rtps_sm_rdentity_id_kind, ett_rtps_rdentity, "readerEntityId", NULL);
  offset += 4;

  /* writerEntityId */
  rtps_util_add_entity_id(tree, tvb, offset, hf_rtps_sm_wrentity_id, hf_rtps_sm_wrentity_id_key,
                        hf_rtps_sm_wrentity_id_kind, ett_rtps_wrentity, "writerEntityId", &wid);
  offset += 4;
  guid->entity_id = wid;
  guid->fields_present |= GUID_HAS_ENTITY_ID;
  rtps_util_topic_info_add_tree(tree, tvb, offset, guid);

  /* Sequence number */
  if (is_session) {
    rtps_util_add_seq_number(tree, tvb, offset, encoding, "writerSessionSeqNumber");
    offset += 8;

    rtps_util_add_seq_number(tree, tvb, offset, encoding, "writerVirtualSeqNumber");
    offset += 8;
  } else {
    coherent_set_entity_info_object.writer_seq_number = rtps_util_add_seq_number(tree, tvb, offset,
      encoding, "writerSeqNumber");
    coherent_set_entity_info_object.guid = *guid;
    offset += 8;
  }

  /* InlineQos */
  if ((flags & FLAG_RTPS_DATA_Q) != 0) {
    gboolean is_inline_qos = TRUE;
    offset = dissect_parameter_sequence(tree, pinfo, tvb, offset, encoding,
                        octets_to_next_header - (offset - old_offset) + 4,
                        "inlineQos", 0x0200, &status_info, vendor_id, is_inline_qos, &coherent_set_entity_info_object);
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
      proto_tree *rtps_pm_tree;
      proto_tree *guid_tree;
      guint32 kind;
      guint32 encapsulation_id, encapsulation_len;
      proto_item *ti;
      rtps_pm_tree = proto_tree_add_subtree(tree, tvb, offset,
                        octets_to_next_header - (offset - old_offset) + 4,
                        ett_rtps_part_message_data, &ti, "ParticipantMessageData");

      /* Encapsulation ID */
      proto_tree_add_item_ret_uint(rtps_pm_tree, hf_rtps_param_serialize_encap_kind, tvb, offset, 2, ENC_BIG_ENDIAN, &encapsulation_id);
      offset += 2;

      encoding = get_encapsulation_endianness(encapsulation_id);

      /* Encapsulation length (or option) */
      proto_tree_add_item_ret_uint(rtps_pm_tree, hf_rtps_param_serialize_encap_len, tvb, offset, 2, ENC_BIG_ENDIAN, &encapsulation_len);
      offset += 2;

      guid_tree = proto_item_add_subtree(ti, ett_rtps_part_message_data);

      rtps_util_add_guid_prefix_v2(guid_tree, tvb, offset, hf_rtps_sm_guid_prefix, hf_rtps_sm_host_id,
                        hf_rtps_sm_app_id, hf_rtps_sm_instance_id, 0);
      offset += 12;

      /* Kind */
      proto_tree_add_item_ret_uint(guid_tree, hf_rtps_encapsulation_kind, tvb, offset, 4, ENC_BIG_ENDIAN, &kind);
      offset += 4;

      rtps_util_add_seq_octets(rtps_pm_tree, pinfo, tvb, offset, encoding,
                               octets_to_next_header - (offset - old_offset) + 4, hf_rtps_data_serialize_data);

    } else if (wid == ENTITYID_P2P_BUILTIN_PARTICIPANT_STATELESS_WRITER) {
      /* PGM stands for Participant Generic Message */
      proto_tree * rtps_pgm_tree, * guid_tree, * message_identity_tree;
      proto_item *ti;
      guint32 encapsulation_id, encapsulation_opt;
      gint32 alignment_zero;
      guint64 sequence_number;

      ti = proto_tree_add_boolean_format(tree, hf_rtps_pgm, tvb, offset,
              octets_to_next_header - (offset - old_offset) + 4, TRUE, "Participant Generic Message");
      rtps_pgm_tree = proto_item_add_subtree(ti, ett_rtps_pgm_data);

      proto_tree_add_item_ret_uint(rtps_pgm_tree, hf_rtps_param_serialize_encap_kind,
              tvb, offset, 2, ENC_BIG_ENDIAN, &encapsulation_id);
      encoding = get_encapsulation_endianness(encapsulation_id);

      offset += 2;
      proto_tree_add_item_ret_uint(rtps_pgm_tree, hf_rtps_param_serialize_encap_len,
              tvb, offset, 2, ENC_BIG_ENDIAN, &encapsulation_opt);

      offset += 2;
      alignment_zero = offset;
        /* Message Identity */
      message_identity_tree = proto_tree_add_subtree(rtps_pgm_tree, tvb, offset,
                          24 , ett_rtps_message_identity, &ti, "Message Identity");

      guid_tree = proto_item_add_subtree(ti, ett_rtps_message_identity);
      proto_item_append_text(guid_tree, " (");
      rtps_util_add_generic_guid_v2(guid_tree, tvb, offset,
              hf_rtps_message_identity_source_guid, hf_rtps_param_host_id, hf_rtps_param_app_id,
              hf_rtps_param_instance_id, hf_rtps_param_entity, hf_rtps_param_entity_key,
              hf_rtps_param_hf_entity_kind, guid_tree);
      offset += 16;

      proto_tree_add_item(message_identity_tree, hf_rtps_sm_seq_number, tvb, offset, 8, encoding);

      /* This snippet shows the sequence number in the parent tree */
      sequence_number = tvb_get_guint64(tvb, offset, encoding);
      proto_item_append_text(guid_tree, ", sn: %" PRIu64 ")",
              sequence_number);
      offset += 8;

        /* Related Message Identity */
      message_identity_tree = proto_tree_add_subtree(rtps_pgm_tree, tvb, offset,
                          24 , ett_rtps_related_message_identity, &ti, "Related Message Identity");

      guid_tree = proto_item_add_subtree(ti, ett_rtps_related_message_identity);
      proto_item_append_text(guid_tree, " (");
      rtps_util_add_generic_guid_v2(guid_tree, tvb, offset,
              hf_rtps_message_identity_source_guid, hf_rtps_param_host_id, hf_rtps_param_app_id,
              hf_rtps_param_instance_id, hf_rtps_param_entity, hf_rtps_param_entity_key,
              hf_rtps_param_hf_entity_kind, guid_tree);
      offset += 16;

      proto_tree_add_item(message_identity_tree, hf_rtps_sm_seq_number, tvb,
                            offset, 8, encoding);

      /* This snippet shows the sequence number in the parent tree */
      sequence_number = tvb_get_guint64(tvb, offset, encoding);
      proto_item_append_text(guid_tree, ", sn: %" PRIu64 ")",
              sequence_number);
      offset += 8;

      guid_tree = proto_item_add_subtree(rtps_pgm_tree, ett_rtps_pgm_data);
      rtps_util_add_generic_guid_v2(guid_tree, tvb, offset,
              hf_rtps_pgm_dst_participant_guid, hf_rtps_param_host_id, hf_rtps_param_app_id,
              hf_rtps_param_instance_id, hf_rtps_param_entity, hf_rtps_param_entity_key,
              hf_rtps_param_hf_entity_kind, NULL);
      offset += 16;

      guid_tree = proto_item_add_subtree(rtps_pgm_tree, ett_rtps_pgm_data);
      rtps_util_add_generic_guid_v2(guid_tree, tvb, offset,
              hf_rtps_pgm_dst_endpoint_guid, hf_rtps_param_host_id, hf_rtps_param_app_id,
              hf_rtps_param_instance_id, hf_rtps_param_entity, hf_rtps_param_entity_key,
              hf_rtps_param_hf_entity_kind, NULL);
      offset += 16;

      guid_tree = proto_item_add_subtree(rtps_pgm_tree, ett_rtps_pgm_data);
      rtps_util_add_generic_guid_v2(guid_tree, tvb, offset,
              hf_rtps_pgm_src_endpoint_guid, hf_rtps_param_host_id, hf_rtps_param_app_id,
              hf_rtps_param_instance_id, hf_rtps_param_entity, hf_rtps_param_entity_key,
              hf_rtps_param_hf_entity_kind, NULL);
      offset += 16;

      offset = rtps_util_add_string(rtps_pgm_tree, tvb, offset, hf_rtps_pgm_message_class_id, encoding);

      rtps_util_add_data_holder_seq(rtps_pgm_tree, tvb, pinfo, offset,
              encoding, alignment_zero);
    } else if (wid == ENTITYID_RTI_BUILTIN_LOCATOR_PING_WRITER) {
      proto_tree * locator_ping_tree, *guid_tree;
      proto_item *ti;
      guint32 encapsulation_id, encapsulation_opt;

      locator_ping_tree = proto_tree_add_subtree(tree, tvb, offset,
                          octets_to_next_header - (offset - old_offset) + 4,
                          ett_rtps_locator_ping_tree, &ti, "Locator Ping Message");

      /* Encapsulation Id */
      proto_tree_add_item_ret_uint(locator_ping_tree, hf_rtps_encapsulation_id,
                tvb, offset, 2, ENC_BIG_ENDIAN, &encapsulation_id);
      offset += 2;
      encoding = get_encapsulation_endianness(encapsulation_id);

      /* Encapsulation length (or option) */
      proto_tree_add_item_ret_uint(locator_ping_tree, hf_rtps_encapsulation_options,
                tvb, offset, 2, ENC_BIG_ENDIAN, &encapsulation_opt);
      offset += 2;

      guid_tree = proto_item_add_subtree(ti, ett_rtps_generic_guid);
      rtps_util_add_generic_guid_v2(guid_tree, tvb, offset,
                      hf_rtps_source_participant_guid, hf_rtps_param_host_id, hf_rtps_param_app_id,
                      hf_rtps_param_instance_id, hf_rtps_param_entity, hf_rtps_param_entity_key,
                      hf_rtps_param_hf_entity_kind, NULL);
      offset += 16;
      rtps_util_add_locator_t(locator_ping_tree, pinfo, tvb, offset, encoding,
              "Destination Locator");

    } else if (wid == ENTITYID_RTI_BUILTIN_SERVICE_REQUEST_WRITER) {
      /*
      struct ServiceRequest {
             long service_id;  //@key
             GUID_t instance_id; //@key
             sequence<octet> request_body;
      }; //@Extensibility EXTENSIBLE_EXTENSIBILITY
      */
      proto_tree * service_request_tree, * guid_tree;
      proto_item *ti;
      guint32 encapsulation_id, encapsulation_opt;
      gint32 service_id;

      ti = proto_tree_add_boolean_format(tree, hf_rtps_srm, tvb, offset,
              octets_to_next_header - (offset - old_offset) + 4,
              TRUE, "Service Request Message");
      service_request_tree = proto_item_add_subtree(ti, ett_rtps_service_request_tree);

      /* Encapsulation Id */
      proto_tree_add_item_ret_uint(service_request_tree, hf_rtps_encapsulation_id,
                tvb, offset, 2, ENC_BIG_ENDIAN, &encapsulation_id);
      offset += 2;
      encoding = get_encapsulation_endianness(encapsulation_id);
        /* Encapsulation length (or option) */
      proto_tree_add_item_ret_uint(service_request_tree, hf_rtps_encapsulation_options, tvb,
                offset, 2, ENC_BIG_ENDIAN, &encapsulation_opt);
      offset += 2;

      proto_tree_add_item_ret_int(service_request_tree, hf_rtps_srm_service_id, tvb,
                offset, 4, encoding, &service_id);
      offset += 4;
      guid_tree = proto_item_add_subtree(ti, ett_rtps_generic_guid);
      rtps_util_add_generic_guid_v2(guid_tree, tvb, offset,
                      hf_rtps_srm_instance_id, hf_rtps_param_host_id, hf_rtps_param_app_id,
                      hf_rtps_param_instance_id, hf_rtps_param_entity, hf_rtps_param_entity_key,
                      hf_rtps_param_hf_entity_kind, NULL);
      offset += 16;
      rtps_util_add_rti_service_request(service_request_tree, pinfo, tvb, offset,
                encoding, service_id);

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

      from_builtin_writer =
        (((wid & 0xc2) == 0xc2) || ((wid & 0xc3) == 0xc3)) ? TRUE : FALSE;
      /* At the end still dissect the rest of the bytes as raw data */
      dissect_serialized_data(tree, pinfo, tvb, offset,
                        octets_to_next_header - (offset - old_offset) + 4,
                        label, vendor_id, from_builtin_writer, guid, NOT_A_FRAGMENT);
    }
  }
  rtps_util_detect_coherent_set_end_empty_data_case(&coherent_set_entity_info_object);
  append_status_info(pinfo, wid, status_info);
}

/* *********************************************************************** */
/* *                 R T P S _ D A T A _ F R A G _ [SESSION]             * */
/* *********************************************************************** */
static void dissect_RTPS_DATA_FRAG_kind(tvbuff_t *tvb, packet_info *pinfo, gint offset, guint8 flags,
                const guint encoding, int octets_to_next_header, proto_tree *tree,
                guint16 vendor_id, gboolean is_session, endpoint_guid *guid) {
  /*
   * There are two kinds of DATA_FRAG, RTPS_DATA_FRAG and RTPS_DATA_FRAG_SESSION
   * the only difference is that RTPS_DATA_FRAG_SESSION has an extra sequence number after
   * writerSeqNum.
   *
   * RTPS_DATA_FRAG:
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
   *
   *
   * RTPS_DATA_FRAG_SESSION:
   * 0...2...........7...............15.............23...............31
   * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   * |RTPS.._SESSION |X|X|X|X|X|K|Q|E|      octetsToNextHeader       |
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
   * + SequenceNumber virtualSeqNum                                  +
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
  guint64 sample_seq_number = 0;
  guint32 frag_number = 0, frag_size = 0, sample_size = 0, num_frags = 0;
  guint32 wid;                  /* Writer EntityID */
  gboolean from_builtin_writer;
  guint32 status_info = 0xffffffff;
  proto_item *octet_item;
  coherent_set_entity_info coherent_set_entity_info_object;

  proto_tree_add_bitmask_value(tree, tvb, offset + 1, hf_rtps_sm_flags, ett_rtps_flags, RTPS_DATA_FRAG_FLAGS, flags);

  octet_item = proto_tree_add_item(tree, hf_rtps_sm_octets_to_next_header, tvb,
                        offset + 2, 2, encoding);

  /* Calculates the minimum length for this submessage
   * RTPS_DATA_FRAG_SESSION len = RTPS_DATA_FRAG len + 8 (extra virtualSequenceNum field).
   */
  min_len = (is_session)
        ? 44
        : 36;
  if ((flags & FLAG_RTPS_DATA_FRAG_Q) != 0) min_len += 4;

  if (octets_to_next_header < min_len) {
    expert_add_info_format(pinfo, octet_item, &ei_rtps_sm_octets_to_next_header_error, "(Error: should be >= %u)", min_len);
    return;
  }

  offset += 4;

  /* extraFlags */
  proto_tree_add_item(tree, hf_rtps_extra_flags, tvb, offset, 2, ENC_BIG_ENDIAN);
  offset += 2;

  /* octetsToInlineQos */
  proto_tree_add_item(tree, hf_rtps_octets_to_inline_qos, tvb, offset, 2, encoding);
  offset += 2;

  /* readerEntityId */
  rtps_util_add_entity_id(tree, tvb, offset, hf_rtps_sm_rdentity_id, hf_rtps_sm_rdentity_id_key,
                        hf_rtps_sm_rdentity_id_kind, ett_rtps_rdentity, "readerEntityId", NULL);
  offset += 4;

  /* writerEntityId */
  rtps_util_add_entity_id(tree, tvb, offset, hf_rtps_sm_wrentity_id, hf_rtps_sm_wrentity_id_key,
                        hf_rtps_sm_wrentity_id_kind, ett_rtps_wrentity, "writerEntityId", &wid);
  offset += 4;
  guid->entity_id = wid;
  guid->fields_present |= GUID_HAS_ENTITY_ID;
  rtps_util_topic_info_add_tree(tree, tvb, offset, guid);


  /* Sequence number */
  coherent_set_entity_info_object.writer_seq_number = rtps_util_add_seq_number(tree, tvb, offset,
    encoding, "writerSeqNumber");
  coherent_set_entity_info_object.guid = *guid;
  offset += 8;

  /* virtual Sequence Number (Only in RTPS_DATA_FRAG_SESSION)*/
  if (is_session) {
      rtps_util_add_seq_number(tree, tvb, offset, encoding, "virtualSeqNumber");
      offset += 8;
  }
  /* Fragment number */
  proto_tree_add_item_ret_uint(tree, hf_rtps_data_frag_number, tvb, offset, 4, encoding, &frag_number);
  offset += 4;

  /* Fragments in submessage */
  proto_tree_add_item_ret_uint(tree, hf_rtps_data_frag_num_fragments, tvb, offset, 2, encoding, &num_frags);
  offset += 2;

  /* Fragment size */
  proto_tree_add_item_ret_uint(tree, hf_rtps_data_frag_size, tvb, offset, 2, encoding, &frag_size);
  offset += 2;

  /* sampleSize */
  proto_tree_add_item_ret_uint(tree, hf_rtps_data_frag_sample_size, tvb, offset, 4, encoding, &sample_size);
  offset += 4;

  /* InlineQos */
  if ((flags & FLAG_RTPS_DATA_FRAG_Q) != 0) {
    gboolean is_inline_qos = TRUE;
    offset = dissect_parameter_sequence(tree, pinfo, tvb, offset, encoding,
                        octets_to_next_header - (offset - old_offset) + 4,
                        "inlineQos", 0x0200, &status_info, vendor_id, is_inline_qos, &coherent_set_entity_info_object);
  }

  /* SerializedData */
  {
    char label[20];
    snprintf(label, 9, "fragment");
    if ((flags & FLAG_RTPS_DATA_FRAG_K) != 0) {
        snprintf(label, 14, "serializedKey");
    }
    from_builtin_writer =
      (((wid & 0xc2) == 0xc2) || ((wid & 0xc3) == 0xc3)) ? TRUE : FALSE;

    guint32 frag_index_in_submessage = 0, this_frag_number = 0, this_frag_size = 0, fragment_offset = 0;
    gboolean more_fragments = FALSE;
    if (enable_rtps_reassembly) {
      tvbuff_t* new_tvb = NULL;
      fragment_head *frag_msg = NULL;
      while(frag_index_in_submessage < num_frags) {
        this_frag_number = frag_number + frag_index_in_submessage;
        more_fragments = (this_frag_number * frag_size < sample_size);
        this_frag_size = more_fragments ? frag_size : (sample_size - ((this_frag_number - 1) * frag_size));
        fragment_offset = this_frag_number == 1 ? 0 : (((this_frag_number - 1) * frag_size));
        pinfo->fragmented = TRUE;
        frag_msg = fragment_add_check(&rtps_reassembly_table,
            tvb, offset, pinfo,
            (guint32)sample_seq_number, /* ID for fragments belonging together */
            (void *)guid, /* make sure only fragments from the same writer are considered for reassembly */
            fragment_offset, /* fragment offset */
            this_frag_size, /* fragment length */
            more_fragments); /* More fragments? */

        new_tvb = process_reassembled_data(tvb, offset + (frag_index_in_submessage * frag_size), pinfo,
            "Reassembled sample", frag_msg, &rtps_frag_items,
            NULL, tree);

        if (frag_index_in_submessage == 0) {
          append_status_info(pinfo, wid, status_info);
          if (frag_msg) { /* Reassembled */
            col_append_fstr(pinfo->cinfo, COL_INFO, " [Reassembled]");
          } else { /* Not last packet of reassembled Short Message */
            col_append_fstr(pinfo->cinfo, COL_INFO," [RTPS fragment]");
          }
        }

        if (new_tvb) {
            snprintf(label, 19, "reassembled sample");
            dissect_serialized_data(tree, pinfo, new_tvb, 0,
                sample_size, label, vendor_id, from_builtin_writer, guid, NOT_A_FRAGMENT);
            break;
        } else {
            snprintf(label, 15, "fragment [%d]", frag_index_in_submessage);
            dissect_serialized_data(tree, pinfo, tvb, offset + (frag_index_in_submessage * frag_size),
                this_frag_size, label, vendor_id, from_builtin_writer, NULL, this_frag_number);
        }
        frag_index_in_submessage++;
      }
    } else {
      while (frag_index_in_submessage < num_frags) {
        this_frag_number = frag_number + frag_index_in_submessage;
        more_fragments = (this_frag_number * frag_size < sample_size);
        this_frag_size = more_fragments ? frag_size : (sample_size - ((this_frag_number - 1) * frag_size));
        fragment_offset = frag_index_in_submessage * frag_size;
        snprintf(label, 20, "fragment [%d]", frag_index_in_submessage);
        dissect_serialized_data(tree, pinfo, tvb, offset + fragment_offset,
            this_frag_size, label, vendor_id, from_builtin_writer, NULL, this_frag_number);
        frag_index_in_submessage++;
        }
      append_status_info(pinfo, wid, status_info);
    }
  }
  rtps_util_detect_coherent_set_end_empty_data_case(&coherent_set_entity_info_object);
}

/* *********************************************************************** */
/* *                 R T P S _ D A T A _ B A T C H                       * */
/* *********************************************************************** */
static void dissect_RTPS_DATA_BATCH(tvbuff_t *tvb, packet_info *pinfo, gint offset,
                guint8 flags, const guint encoding, int octets_to_next_header,
                proto_tree *tree, guint16 vendor_id, endpoint_guid *guid) {
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
  gint32 octetsToSLEncapsulationId;
  gint32 sampleListOffset;
  guint16 encapsulation_id;
  gboolean try_dissection_from_type_object = FALSE;
  guint16 *sample_info_flags = NULL;
  guint32 *sample_info_length = NULL;
  gint32  sample_info_count = 0,
          sample_info_max = rtps_max_batch_samples_dissected;
  proto_item *octet_item;
  rtps_dissector_data * data = NULL;
  gboolean is_compressed = FALSE;
  gboolean uncompressed_ok = FALSE;
  proto_tree *compressed_subtree = NULL;
  tvbuff_t *data_holder_tvb = tvb;
  tvbuff_t *compressed_tvb = NULL;
  proto_tree *dissected_data_holdeer_tree = tree;


  data = wmem_new(wmem_packet_scope(), rtps_dissector_data);
  data->info_displayed = FALSE;
  data->encapsulation_id = 0;

  proto_tree_add_bitmask_value(tree, tvb, offset + 1, hf_rtps_sm_flags, ett_rtps_flags, RTPS_DATA_BATCH_FLAGS, flags);

  octet_item = proto_tree_add_item(tree, hf_rtps_sm_octets_to_next_header, tvb,
                        offset + 2, 2, encoding);

  /* Calculates the minimum length for this submessage */
  min_len = 44;
  if ((flags & FLAG_RTPS_DATA_BATCH_Q) != 0) min_len += 4;

  if (octets_to_next_header < min_len) {
    expert_add_info_format(pinfo, octet_item, &ei_rtps_sm_octets_to_next_header_error, "(Error: should be >= %u)", min_len);
    return;
  }

  offset += 4;

  /* extraFlags */
  proto_tree_add_item(tree, hf_rtps_extra_flags, tvb, offset, 2, ENC_BIG_ENDIAN);
  offset += 2;

  /* octetsToInlineQos */
  proto_tree_add_item(tree, hf_rtps_octets_to_inline_qos, tvb, offset, 2, encoding);
  offset += 2;


  /* readerEntityId */
  rtps_util_add_entity_id(tree, tvb, offset, hf_rtps_sm_rdentity_id, hf_rtps_sm_rdentity_id_key,
                        hf_rtps_sm_rdentity_id_kind, ett_rtps_rdentity, "readerEntityId", NULL);
  offset += 4;

  /* writerEntityId */
  rtps_util_add_entity_id(tree, tvb, offset, hf_rtps_sm_wrentity_id, hf_rtps_sm_wrentity_id_key,
                        hf_rtps_sm_wrentity_id_kind, ett_rtps_wrentity, "writerEntityId", &wid);
  offset += 4;
  guid->entity_id = wid;
  guid->fields_present |= GUID_HAS_ENTITY_ID;
  rtps_util_topic_info_add_tree(tree, tvb, offset, guid);


  /* Batch sequence number */
  rtps_util_add_seq_number(tree, tvb, offset, encoding, "batchSeqNumber");
  offset += 8;

  /* First stample sequence number */
  rtps_util_add_seq_number(tree, tvb, offset, encoding, "firstSampleSeqNumber");
  offset += 8;

  /* offsetToLastSampleSN */
  proto_tree_add_item(tree, hf_rtps_data_batch_offset_to_last_sample_sn, tvb, offset, 4, encoding);
  offset += 4;

  /* batchSampleCount */
  proto_tree_add_item(tree, hf_rtps_data_batch_sample_count, tvb, offset, 4, encoding);
  offset += 4;

  /* Parameter list (if Q==1) */
  /* InlineQos */
  if ((flags & FLAG_RTPS_DATA_BATCH_Q) != 0) {
    offset = dissect_parameter_sequence(tree, pinfo, tvb, offset, encoding,
                        octets_to_next_header - (offset - old_offset) + 4,
                        "batchInlineQos", 0x0200, &status_info, vendor_id, FALSE, NULL);
  }

  /* octetsToSLEncapsulationId */
  octetsToSLEncapsulationId = tvb_get_guint32(tvb, offset, encoding);
  proto_tree_add_item(tree, hf_rtps_data_batch_octets_to_sl_encap_id, tvb,
                        offset, 4, octetsToSLEncapsulationId);
  offset += 4;
  sampleListOffset = offset + octetsToSLEncapsulationId;


  /* Sample info list */
  {
    proto_item *ti, *list_item;
    proto_tree *sil_tree;
    sample_info_count = 0;

    sil_tree = proto_tree_add_subtree(tree, tvb, offset, octetsToSLEncapsulationId,
            ett_rtps_sample_info_list, &list_item, "Sample Info List");

    /* Allocate sample_info_flags and sample_info_length
     * to store a copy of the flags for each sample info */
    if (rtps_max_batch_samples_dissected == 0) {
      sample_info_max = 1024;   /* Max size of sampleInfo shown */
    }
    sample_info_flags = (guint16 *)wmem_alloc(wmem_packet_scope(), sizeof(guint16) *sample_info_max);
    sample_info_length = (guint32 *)wmem_alloc(wmem_packet_scope(), sizeof(guint32) *sample_info_max);

    /* Sample Info List: start decoding the sample info list until the offset
     * is greater or equal than 'sampleListOffset' */
    while (offset < sampleListOffset) {
      guint16 flags2;
      /*guint16 octetsToInlineQos;*/
      gint min_length;
      proto_tree *si_tree;
      gint offset_begin_sampleinfo = offset;

      if (rtps_max_batch_samples_dissected > 0 && (guint)sample_info_count >= rtps_max_batch_samples_dissected) {
        expert_add_info(pinfo, list_item, &ei_rtps_more_samples_available);
        offset = sampleListOffset;
        break;
      }

      si_tree = proto_tree_add_subtree_format(sil_tree, tvb, offset, -1, ett_rtps_sample_info, &ti, "sampleInfo[%d]", sample_info_count);

      flags2 = tvb_get_ntohs(tvb, offset); /* Flags are always big endian */
      sample_info_flags[sample_info_count] = flags2;
      proto_tree_add_bitmask_value(si_tree, tvb, offset, hf_rtps_sm_flags2, ett_rtps_flags, RTPS_SAMPLE_INFO_FLAGS16, flags2);
      offset += 2;
      proto_tree_add_item(si_tree, hf_rtps_data_batch_octets_to_inline_qos, tvb,
                        offset, 2, encoding);
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
      proto_tree_add_item_ret_uint(si_tree, hf_rtps_data_batch_serialized_data_length, tvb,
                        offset, 4, encoding, &sample_info_length[sample_info_count]);
      offset += 4;

      /* Timestamp [only if T==1] */
      if ((flags2 & FLAG_SAMPLE_INFO_T) != 0) {
        rtps_util_add_timestamp(si_tree, tvb, offset, encoding, hf_rtps_data_batch_timestamp);
        offset += 8;
      }

      /* Offset SN [only if O==1] */
      if ((flags2 & FLAG_SAMPLE_INFO_O) != 0) {
        proto_tree_add_item(si_tree, hf_rtps_data_batch_offset_sn, tvb, offset, 4, encoding);
        offset += 4;
      }

      /* Parameter list [only if Q==1] */
      if ((flags2 & FLAG_SAMPLE_INFO_Q) != 0) {
        offset = dissect_parameter_sequence(si_tree, pinfo, tvb, offset, encoding,
                        octets_to_next_header - (offset - old_offset) + 4,
                        "sampleInlineQos", 0x0200, &status_info, vendor_id, FALSE, NULL);
      }
      proto_item_set_len(ti, offset - offset_begin_sampleinfo);
      sample_info_count++;
    } /*   while (offset < sampleListOffset) */
  }

  /* Dissects the encapsulated data heder and uncompress the tvb  if it is compressed and
     it can be uncompressed */
  offset = rtps_prepare_encapsulated_data(
      tree,
      pinfo,
      tvb,
      offset,
      tvb_reported_length(tvb) - offset,
      TRUE,
      &encapsulation_id,
      NULL,
      NULL,
      NULL,
      NULL,
      &is_compressed,
      &uncompressed_ok,
      &compressed_tvb,
      &compressed_subtree);
  data->encapsulation_id = encapsulation_id;
  if (is_compressed && uncompressed_ok) {
      data_holder_tvb = compressed_tvb;
      offset = 0;
      dissected_data_holdeer_tree = compressed_subtree;
      octets_to_next_header = tvb_reported_length(data_holder_tvb);
      old_offset = 0;
  }

  /* If it is compressed but not uncompressed don't try to dissect */
  if (is_compressed == uncompressed_ok) {
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
      if ((octets_to_next_header - (offset - old_offset) > 0)) {
          proto_item *ti;
          proto_tree *sil_tree;
          gint count = 0;

          sil_tree = proto_tree_add_subtree(
              dissected_data_holdeer_tree,
              data_holder_tvb,
              offset,
              -1,
              ett_rtps_sample_batch_list,
              &ti,
              "Serialized Sample List");
          for (count = 0; count < sample_info_count; ++count) {
              /* Ensure there are enough bytes in the buffer to dissect the next sample */
              if (octets_to_next_header - (offset - old_offset) + 4 < (gint)sample_info_length[count]) {
                  expert_add_info_format(pinfo, ti, &ei_rtps_parameter_value_invalid, "Error: not enough bytes to dissect sample");
                  return;
              }
              /* We have enough bytes to dissect the next sample, so we update the rtps_dissector_data
               *  "position in the batch" value and dissect the sample
               */
              data->position_in_batch = count;
              if (encapsulation_id == ENCAPSULATION_CDR_LE ||
                  encapsulation_id == ENCAPSULATION_CDR_BE ||
                  encapsulation_id == ENCAPSULATION_CDR2_LE ||
                  encapsulation_id == ENCAPSULATION_CDR2_BE ||
                  encapsulation_id == ENCAPSULATION_PL_CDR_LE ||
                  encapsulation_id == ENCAPSULATION_PL_CDR_BE) {
                  try_dissection_from_type_object = TRUE;
              }
              if ((sample_info_flags[count] & FLAG_SAMPLE_INFO_K) != 0) {
                  proto_tree_add_bytes_format(sil_tree, hf_rtps_serialized_key,
                      data_holder_tvb, offset, sample_info_length[count], NULL, "serializedKey[%d]", count);
              } else {
                  if (!rtps_util_topic_info_add_column_info_and_try_dissector(
                      sil_tree, pinfo, data_holder_tvb, offset, guid, data, get_encapsulation_endianness(encapsulation_id), get_encapsulation_version(encapsulation_id), try_dissection_from_type_object)) {
                      proto_tree_add_bytes_format(sil_tree, hf_rtps_serialized_data,
                          data_holder_tvb, offset, sample_info_length[count], NULL, "serializedData[%d]", count);
                  }
              }
              offset += sample_info_length[count];
          }
      }
  } else {
      /* If uncompression went wrong still need to add the topic column info */
      rtps_util_topic_info_add_column_info(pinfo, guid, data);
  }
  append_status_info(pinfo, wid, status_info);
}

/* *********************************************************************** */
/* *                                 G A P                               * */
/* *********************************************************************** */
static void dissect_GAP(tvbuff_t *tvb, packet_info *pinfo, gint offset,
                guint8 flags, const guint encoding, int octets_to_next_header,
                proto_tree *tree, endpoint_guid *guid) {
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
  proto_item *octet_item;
  guint32 wid;
  proto_tree_add_bitmask_value(tree, tvb, offset + 1, hf_rtps_sm_flags, ett_rtps_flags, GAP_FLAGS, flags);

  octet_item = proto_tree_add_item(tree, hf_rtps_sm_octets_to_next_header, tvb,
                        offset + 2, 2, encoding);

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
                        ett_rtps_wrentity, "writerEntityId", &wid);
  offset += 4;
  guid->entity_id = wid;
  guid->fields_present |= GUID_HAS_ENTITY_ID;
  rtps_util_topic_info_add_tree(tree, tvb, offset, guid);


 /* First Sequence Number */
  rtps_util_add_seq_number(tree, tvb, offset, encoding, "gapStart");
  offset += 8;

  /* Bitmap */
  rtps_util_add_bitmap(tree, tvb, offset, encoding, "gapList", FALSE);
}


/* *********************************************************************** */
/* *                           I N F O _ T S                             * */
/* *********************************************************************** */
static void dissect_INFO_TS(tvbuff_t *tvb, packet_info *pinfo, gint offset, guint8 flags,
                const guint encoding, int octets_to_next_header, proto_tree *tree) {
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
  proto_item *octet_item;

  proto_tree_add_bitmask_value(tree, tvb, offset + 1, hf_rtps_sm_flags, ett_rtps_flags, INFO_TS_FLAGS, flags);

  octet_item = proto_tree_add_item(tree,
                        hf_rtps_sm_octets_to_next_header,
                        tvb,
                        offset + 2,
                        2,
                        encoding);

  min_len = 0;
  if ((flags & FLAG_INFO_TS_T) == 0) min_len += 8;

  if (octets_to_next_header != min_len) {
    expert_add_info_format(pinfo, octet_item, &ei_rtps_sm_octets_to_next_header_error, "(Error: should be == %u)", min_len);
    return;
  }

  offset += 4;

  if ((flags & FLAG_INFO_TS_T) == 0) {
    rtps_util_add_timestamp(tree,
                        tvb,
                        offset,
                        encoding,
                        hf_rtps_info_ts_timestamp);
  }
}


/* *********************************************************************** */
/* *                           I N F O _ S R C                           * */
/* *********************************************************************** */
static void dissect_INFO_SRC(tvbuff_t *tvb, packet_info *pinfo, gint offset, guint8 flags,
                const guint encoding, int octets_to_next_header, proto_tree *tree, guint16 rtps_version) {
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
  proto_item *octet_item;
  guint16 version;

  proto_tree_add_bitmask_value(tree, tvb, offset + 1, hf_rtps_sm_flags, ett_rtps_flags, INFO_SRC_FLAGS, flags);

  octet_item = proto_tree_add_item(tree, hf_rtps_sm_octets_to_next_header, tvb,
                        offset + 2, 2, encoding);

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

  /* Use version field to determine what to display */
  version = tvb_get_ntohs(tvb, offset+4);
  if (version < 0x102) {
    proto_tree_add_item(tree, hf_rtps_info_src_ip, tvb, offset, 4, encoding);
  } else {
    proto_tree_add_item(tree, hf_rtps_info_src_unused, tvb, offset, 4, encoding);
  }

  offset += 4;

  rtps_util_add_protocol_version(tree, tvb, offset);
  offset += 2;

  /* Vendor ID */
  rtps_util_add_vendor_id(tree, tvb, offset);
  offset += 2;

  if (rtps_version < 0x0200) {
    rtps_util_add_guid_prefix_v1(tree, tvb, offset,
                        hf_rtps_sm_guid_prefix_v1, hf_rtps_sm_host_id, hf_rtps_sm_app_id,
                        hf_rtps_sm_instance_id_v1, hf_rtps_sm_app_kind,
                        NULL);   /* Use default 'guidPrefix' */
  } else {
      rtps_util_add_guid_prefix_v2(tree, tvb, offset, hf_rtps_guid_prefix_src,
          hf_rtps_host_id, hf_rtps_app_id, hf_rtps_sm_instance_id, hf_rtps_guid_prefix);
  }
}


/* *********************************************************************** */
/* *                    I N F O _ R E P L Y _ I P 4                      * */
/* *********************************************************************** */
static void dissect_INFO_REPLY_IP4(tvbuff_t *tvb, packet_info *pinfo, gint offset, guint8 flags,
                const guint encoding, int octets_to_next_header, proto_tree *tree) {
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
  proto_item *octet_item;

  proto_tree_add_bitmask_value(tree, tvb, offset + 1, hf_rtps_sm_flags, ett_rtps_flags, INFO_REPLY_IP4_FLAGS, flags);

  octet_item = proto_tree_add_item(tree,
                        hf_rtps_sm_octets_to_next_header,
                        tvb,
                        offset + 2,
                        2,
                        encoding);

  min_len = 8;
  if ((flags & FLAG_INFO_REPLY_IP4_M) != 0) min_len += 8;

  if (octets_to_next_header != min_len) {
    expert_add_info_format(pinfo, octet_item, &ei_rtps_sm_octets_to_next_header_error, "(Error: should be == %u)", min_len);
    return;
  }

  offset += 4;


  /* unicastReplyLocator */
  rtps_util_add_locator_udp_v4(tree, pinfo, tvb, offset,
                        "unicastReplyLocator", encoding);

  offset += 8;

  /* multicastReplyLocator */
  if ((flags & FLAG_INFO_REPLY_IP4_M) != 0) {
    rtps_util_add_locator_udp_v4(tree, pinfo, tvb, offset,
                        "multicastReplyLocator", encoding);
    /*offset += 8;*/
  }
}

/* *********************************************************************** */
/* *                           I N F O _ D S T                           * */
/* *********************************************************************** */
static void dissect_INFO_DST(tvbuff_t *tvb, packet_info *pinfo, gint offset, guint8 flags,
                const guint encoding, int octets_to_next_header, proto_tree *tree,
                guint16 version, endpoint_guid *dst_guid) {
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
  proto_item *octet_item;

  proto_tree_add_bitmask_value(tree, tvb, offset + 1, hf_rtps_sm_flags, ett_rtps_flags, INFO_DST_FLAGS, flags);

  octet_item = proto_tree_add_item(tree, hf_rtps_sm_octets_to_next_header, tvb,
                        offset + 2, 2, encoding);

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
                        hf_rtps_sm_guid_prefix_v1, hf_rtps_sm_host_id, hf_rtps_sm_app_id,
                        hf_rtps_sm_instance_id_v1, hf_rtps_sm_app_kind,
                        NULL);
  } else {
      rtps_util_add_guid_prefix_v2(tree, tvb, offset, hf_rtps_guid_prefix_dst,
          hf_rtps_host_id, hf_rtps_app_id, hf_rtps_sm_instance_id, hf_rtps_guid_prefix);

      dst_guid->host_id = tvb_get_ntohl(tvb, offset);
      dst_guid->app_id = tvb_get_ntohl(tvb, offset + 4);
      dst_guid->instance_id = tvb_get_ntohl(tvb, offset + 8);
      dst_guid->fields_present |= GUID_HAS_HOST_ID|GUID_HAS_APP_ID|GUID_HAS_INSTANCE_ID;
  }
}

/* *********************************************************************** */
/* *                        I N F O _ R E P L Y                          * */
/* *********************************************************************** */
static void dissect_INFO_REPLY(tvbuff_t *tvb, packet_info *pinfo, gint offset, guint8 flags,
                const guint encoding, int octets_to_next_header, proto_tree *tree) {
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
  proto_item *octet_item;

  proto_tree_add_bitmask_value(tree, tvb, offset + 1, hf_rtps_sm_flags, ett_rtps_flags, INFO_REPLY_FLAGS, flags);

  octet_item = proto_tree_add_item(tree,
                        hf_rtps_sm_octets_to_next_header,
                        tvb,
                        offset + 2,
                        2,
                        encoding);

  min_len = 4;
  if ((flags & FLAG_INFO_REPLY_M) != 0) min_len += 4;

  if (octets_to_next_header < min_len) {
    expert_add_info_format(pinfo, octet_item, &ei_rtps_sm_octets_to_next_header_error, "(Error: should be >= %u)", min_len);
    return;
  }

  offset += 4;

  /* unicastReplyLocatorList */
  offset = rtps_util_add_locator_list(tree, pinfo, tvb, offset, "unicastReplyLocatorList", encoding);

  /* multicastReplyLocatorList */
  if ((flags & FLAG_INFO_REPLY_M) != 0) {
    /*offset = */rtps_util_add_locator_list(tree, pinfo, tvb, offset, "multicastReplyLocatorList", encoding);
  }
}

/* *********************************************************************** */
/* *                              RTI CRC                                * */
/* *********************************************************************** */
static void dissect_RTI_CRC(tvbuff_t *tvb, packet_info *pinfo, gint offset, guint8 flags,
        const guint encoding, gint octets_to_next_header,proto_tree *tree) {
   /*
    * 0...2...........7...............15.............23...............31
    * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    * |   RTI_CRC     |X|X|X|X|X|X|X|E|      octetsToNextHeader       |
    * +---------------+---------------+---------------+---------------+
    * |        RTPS Message length (without the 20 bytes header)      |
    * +---------------+---------------+---------------+---------------+
    * |                             CRC32                             |
    * +---------------+---------------+---------------+---------------+
      Total 12 bytes */
   proto_item *octet_item;

   proto_tree_add_bitmask_value(tree, tvb, offset + 1, hf_rtps_sm_flags, ett_rtps_flags, RTI_CRC_FLAGS, flags);

   octet_item = proto_tree_add_item(tree, hf_rtps_sm_octets_to_next_header, tvb,
                         offset + 2, 2, encoding);

   if (octets_to_next_header != 8) {
     expert_add_info_format(pinfo, octet_item, &ei_rtps_sm_octets_to_next_header_error, "(Error: should be == 8)");
     return;
   }

   offset += 4;
   proto_tree_add_item(tree, hf_rtps_sm_rti_crc_number, tvb, offset, 4, encoding);

   offset += 4;
      proto_tree_add_item(tree, hf_rtps_sm_rti_crc_result, tvb, offset, 4, ENC_BIG_ENDIAN);
}

static void dissect_SECURE(tvbuff_t *tvb, packet_info *pinfo _U_, gint offset,
                guint8 flags, const guint encoding _U_, int octets_to_next_header,
                proto_tree *tree, guint16 vendor_id _U_) {

 /* *********************************************************************** */
 /* *                          SECURE SUBMESSAGE                          * */
 /* *********************************************************************** */
 /* 0...2...........7...............15.............23...............31
    * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    * | SECURE SUBMSG |X|X|X|X|X|X|S|E|      octetsToNextHeader       |
    * +---------------+---------------+---------------+---------------+
    * |                    long transformationKind                    |
    * +---------------+---------------+---------------+---------------+
    * |                                                               |
    * +                  octet transformationId[8]                    +
    * |                                                               |
    * +---------------+---------------+---------------+---------------+
    * |                                                               |
    * +                     octet secure_data[]                       +
    * |                                                               |
    * +---------------+---------------+---------------+---------------+
    */
    proto_tree * payload_tree;
    guint local_encoding;
    proto_tree_add_bitmask_value(tree, tvb, offset + 1, hf_rtps_sm_flags, ett_rtps_flags, SECURE_FLAGS, flags);
    local_encoding = ((flags & FLAG_E) != 0) ? ENC_LITTLE_ENDIAN : ENC_BIG_ENDIAN;

    proto_tree_add_item(tree, hf_rtps_sm_octets_to_next_header, tvb, offset + 2, 2, local_encoding);

    offset += 4;

    payload_tree = proto_tree_add_subtree_format(tree, tvb, offset, octets_to_next_header,
                   ett_rtps_secure_payload_tree, NULL, "Secured payload");

    proto_tree_add_item(payload_tree, hf_rtps_secure_secure_data_length, tvb,
                            offset, 4, ENC_BIG_ENDIAN);
    offset += 4;

    proto_tree_add_item(payload_tree, hf_rtps_secure_secure_data, tvb,
                            offset, octets_to_next_header-4, local_encoding);

}

static void dissect_SECURE_PREFIX(tvbuff_t *tvb, packet_info *pinfo _U_, gint offset,
                guint8 flags, const guint encoding, int octets_to_next_header,
                proto_tree *tree, guint16 vendor_id _U_) {
    /*
     * MIG_RTPS_SECURE_RTPS_PREFIX and MIG_RTPS_SECURE_PREFIX share same serialization:
     * 0...2...........8...............16.............24...............32
     * +---------------+---------------+---------------+---------------+
     * | 0x33 / 0x31   |X|X|X|X|X|X|X|E|        octetsToNextHeader     |
     * +---------------+---------------+---------------+---------------+
     * |                                                               |
     * +                SecureDataHeader sec_data_header               +
     * |                                                               |
     * +---------------+---------------+---------------+---------------+
     *
     * where SecureDataHeader is:
     *
     * SecureDataHeader: TransformationIdentifier (kind + key) + plugin_sec_header
     *  0...2...........8...............16.............24...............32
     * +---------------+---------------+---------------+---------------+
     * |                 octet transformation_kind[4]                  |
     * +---------------+---------------+---------------+---------------+
     * |                                                               |
     * +                 octet transformation_key_id[4]                +
     * |                                                               |
     * +---------------+---------------+---------------+---------------+
     * |                                                               |
     * ~                 octet plugin_sec_header[]                     ~
     * |                                                               |
     * +---------------+---------------+---------------+---------------+
     */
  proto_tree * sec_data_header_tree;

  proto_tree_add_bitmask_value(tree, tvb, offset + 1, hf_rtps_sm_flags,
          ett_rtps_flags, SECURE_PREFIX_FLAGS, flags);

  proto_tree_add_item(tree, hf_rtps_sm_octets_to_next_header, tvb, offset + 2,
          2, encoding);
  offset += 4;

  sec_data_header_tree = proto_tree_add_subtree_format(tree, tvb, offset, octets_to_next_header,
          ett_rtps_secure_dataheader_tree, NULL, "Secure Data Header");

  proto_tree_add_item(sec_data_header_tree, hf_rtps_secure_dataheader_transformation_kind, tvb,
          offset, 4, ENC_BIG_ENDIAN);
  offset += 4;

  proto_tree_add_item(sec_data_header_tree, hf_rtps_secure_dataheader_transformation_key_id, tvb,
          offset, 4, encoding);
  offset += 4;

  proto_tree_add_item(sec_data_header_tree, hf_rtps_secure_dataheader_plugin_sec_header, tvb,
          offset, octets_to_next_header-8, encoding);
}

static void dissect_SECURE_POSTFIX(tvbuff_t *tvb, packet_info *pinfo _U_, gint offset,
                guint8 flags, const guint encoding, int octets_to_next_header,
                proto_tree *tree, guint16 vendor_id _U_) {
    /*
     * MIG_RTPS_SECURE_RTPS_POSTFIX and MIG_RTPS_SECURE_POSTFIX share the same serialization:
     * 0...2...........8...............16.............24...............32
     * +---------------+---------------+---------------+---------------+
     * | 0x34 / 0x32   |X|X|X|X|X|X|X|E|        octetsToNextHeader     |
     * +---------------+---------------+---------------+---------------+
     * |                                                               |
     * +                SecureDataTag sec_data_tag                     +
     * |                                                               |
     * +---------------+---------------+---------------+---------------+
     *
     * where SecureDataTag is:
     *  0...2...........8...............16.............24...............32
     * +---------------+---------------+---------------+---------------+
     * |                                                               |
     * ~                 octet plugin_sec_tag[]                        ~
     * |                                                               |
     * +---------------+---------------+---------------+---------------+
     */
  proto_tree * sec_data_tag_tree;

  proto_tree_add_bitmask_value(tree, tvb, offset + 1, hf_rtps_sm_flags,
            ett_rtps_flags, SECURE_POSTFIX_FLAGS, flags);

  proto_tree_add_item(tree, hf_rtps_sm_octets_to_next_header, tvb, offset + 2,
            2, encoding);
  offset += 4;

  sec_data_tag_tree = proto_tree_add_subtree_format(tree, tvb, offset, octets_to_next_header,
            ett_rtps_secure_dataheader_tree, NULL, "Secure Data Tag");

  proto_tree_add_item(sec_data_tag_tree, hf_rtps_secure_datatag_plugin_sec_tag, tvb,
            offset, octets_to_next_header, encoding);
}
/*
 * 0...2...........7...............15.............23...............31
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * | BINDING_PING  |X|X|X|X|X|B|L|E|     octetsToNextHeader        |
 * +---------------+---------------+---------------+---------------+
 * |                 DDS_UnsignedLong rtps_port                    |
 * +---------------+---------------+---------------+---------------+
 * |                                                               |
 * +              DDS_Octet address[12][If L = 0]                  +
 * |                                                               |
 * +                                                               +
 * |                                                               |
 * +---------------+---------------+---------------+---------------+
 * |                                                               |
 * +              DDS_Octet address[16][If L = 1]                  +
 * |                                                               |
 * +                                                               +
 * |                                                               |
 * +                                                               +
 * |                                                               |
 * +---------------+---------------+---------------+---------------+
 *
 */
static void dissect_UDP_WAN_BINDING_PING(tvbuff_t *tvb, packet_info *pinfo _U_, gint offset,
    guint8 flags, const guint encoding, int octets_to_next_header _U_,
    proto_tree *tree, guint16 vendor_id _U_) {

    const guint flags_offset = offset + 1;
    const guint next_header_offset = flags_offset + 1;
    const guint port_offset = next_header_offset + 2;
    const guint address_offset = port_offset + 4;

    proto_tree_add_bitmask_value(tree, tvb, flags_offset, hf_rtps_udpv4_wan_binding_ping_flags,
        ett_rtps_flags, UDPV4_WAN_BINDING_PING_FLAGS, flags);
    proto_tree_add_item(tree, hf_rtps_sm_octets_to_next_header, tvb, next_header_offset,
        2, encoding);
    proto_tree_add_item(tree, hf_rtps_udpv4_wan_binding_ping_port, tvb, port_offset,
        4, encoding);
    /*
     * Address[12] [If L=0] is the only one we currently support, and it maps to:
     * DDS_Octet UUID[9] + 3 bytes of padding.
     */
    if (flags & FLAG_UDPV4_WAN_BINDING_PING_FLAG_L) {
        proto_tree_add_item(
                tree,
                hf_rtps_long_address,
                tvb,
                address_offset,
                LONG_ADDRESS_SIZE,
                encoding);
    } else {
        proto_tree_add_item(
                tree,
                hf_rtps_uuid,
                tvb,
                address_offset,
                UUID_SIZE,
                encoding);
    }
}

static gboolean dissect_rtps_submessage_v2(tvbuff_t *tvb, packet_info *pinfo, gint offset, guint8 flags,
                                           const guint encoding, guint8 submessageId, guint16 vendor_id, gint octets_to_next_header,
                                           proto_tree *rtps_submessage_tree, proto_item *submessage_item,
                                           endpoint_guid * guid, endpoint_guid * dst_guid)
{
  switch (submessageId)
  {
    case SUBMESSAGE_DATA_FRAG:
      dissect_DATA_FRAG(tvb, pinfo, offset, flags, encoding,
          octets_to_next_header, rtps_submessage_tree, vendor_id, guid);
      break;

    case SUBMESSAGE_NOKEY_DATA_FRAG:
      dissect_NOKEY_DATA_FRAG(tvb, pinfo, offset, flags, encoding, octets_to_next_header, rtps_submessage_tree, vendor_id);
      break;

    case SUBMESSAGE_NACK_FRAG:
      dissect_NACK_FRAG(tvb, pinfo, offset, flags, encoding, octets_to_next_header, rtps_submessage_tree);
      break;

    case SUBMESSAGE_ACKNACK_SESSION:
    case SUBMESSAGE_ACKNACK_BATCH:
      dissect_ACKNACK(tvb, pinfo, offset, flags, encoding,
          octets_to_next_header, rtps_submessage_tree, submessage_item, dst_guid);
      break;

    case SUBMESSAGE_APP_ACK:
      dissect_APP_ACK(tvb, pinfo, offset, flags, encoding, octets_to_next_header, rtps_submessage_tree, submessage_item, guid);
      break;

    case SUBMESSAGE_APP_ACK_CONF:
      dissect_APP_ACK_CONF(tvb, pinfo, offset, flags, encoding, octets_to_next_header, rtps_submessage_tree, submessage_item, guid);
      break;

    case SUBMESSAGE_HEARTBEAT_SESSION:
    case SUBMESSAGE_HEARTBEAT_BATCH:
      dissect_HEARTBEAT_BATCH(tvb, pinfo, offset, flags, encoding,
          octets_to_next_header, rtps_submessage_tree, guid);
      break;

    case SUBMESSAGE_HEARTBEAT_FRAG:
      dissect_HEARTBEAT_FRAG(tvb, pinfo, offset, flags, encoding,
          octets_to_next_header, rtps_submessage_tree, guid);
      break;

    case SUBMESSAGE_HEARTBEAT_VIRTUAL:
      dissect_HEARTBEAT_VIRTUAL(tvb, pinfo, offset, flags, encoding,
          octets_to_next_header, rtps_submessage_tree, vendor_id, guid);
      break;

    case SUBMESSAGE_RTPS_DATA_SESSION:
    case SUBMESSAGE_RTPS_DATA:
      dissect_RTPS_DATA(tvb, pinfo, offset, flags, encoding, octets_to_next_header,
              rtps_submessage_tree, vendor_id, (submessageId == SUBMESSAGE_RTPS_DATA_SESSION), guid);
      break;

    case SUBMESSAGE_RTI_DATA_FRAG_SESSION:
    case SUBMESSAGE_RTPS_DATA_FRAG:
      dissect_RTPS_DATA_FRAG_kind(tvb, pinfo, offset, flags, encoding, octets_to_next_header,
                                rtps_submessage_tree, vendor_id, (submessageId == SUBMESSAGE_RTI_DATA_FRAG_SESSION), guid);
      break;

    case SUBMESSAGE_RTPS_DATA_BATCH:
      dissect_RTPS_DATA_BATCH(tvb, pinfo, offset, flags, encoding, octets_to_next_header,
                                rtps_submessage_tree, vendor_id, guid);
      break;

    case SUBMESSAGE_RTI_CRC:
      if (vendor_id == RTPS_VENDOR_RTI_DDS) {
        dissect_RTI_CRC(tvb, pinfo, offset, flags, encoding, octets_to_next_header,
                                rtps_submessage_tree);
      }
      break;
    case SUBMESSAGE_SEC_BODY:
      dissect_SECURE(tvb, pinfo, offset, flags, encoding, octets_to_next_header,
                                rtps_submessage_tree, vendor_id);
      break;
    case SUBMESSAGE_SEC_PREFIX:
    case SUBMESSAGE_SRTPS_PREFIX:
      dissect_SECURE_PREFIX(tvb, pinfo, offset, flags, encoding, octets_to_next_header,
                                rtps_submessage_tree, vendor_id);
      break;
    case SUBMESSAGE_SEC_POSTFIX:
    case SUBMESSAGE_SRTPS_POSTFIX:
      dissect_SECURE_POSTFIX(tvb, pinfo, offset, flags, encoding, octets_to_next_header,
                                rtps_submessage_tree, vendor_id);
      break;
    case SUBMESSAGE_RTI_UDP_WAN_BINDING_PING:
      dissect_UDP_WAN_BINDING_PING(tvb, pinfo, offset, flags, encoding, octets_to_next_header,
            rtps_submessage_tree, vendor_id);
      break;

    default:
      return FALSE;
  }

  return TRUE;
}

static gboolean dissect_rtps_submessage_v1(tvbuff_t *tvb, packet_info *pinfo, gint offset, guint8 flags, const guint encoding,
                                           guint8 submessageId, guint16 version, guint16 vendor_id, gint octets_to_next_header,
                                           proto_tree *rtps_submessage_tree, proto_item *submessage_item,
                                           endpoint_guid * guid, endpoint_guid * dst_guid)
{
  switch (submessageId)
  {
    case SUBMESSAGE_PAD:
      dissect_PAD(tvb, pinfo, offset, flags, encoding, octets_to_next_header, rtps_submessage_tree);
      break;

    case SUBMESSAGE_DATA:
      if (version < 0x0200) {
        dissect_DATA_v1(tvb, pinfo, offset, flags, encoding,
                octets_to_next_header, rtps_submessage_tree);
      } else {
        dissect_DATA_v2(tvb, pinfo, offset, flags, encoding,
                octets_to_next_header, rtps_submessage_tree, vendor_id, guid);
      }
      break;

    case SUBMESSAGE_NOKEY_DATA:
      dissect_NOKEY_DATA(tvb, pinfo, offset, flags, encoding, octets_to_next_header, rtps_submessage_tree,
                         version, vendor_id);
      break;

    case SUBMESSAGE_ACKNACK:
      dissect_ACKNACK(tvb, pinfo, offset, flags, encoding,
		  octets_to_next_header, rtps_submessage_tree, submessage_item, dst_guid);
      break;

    case SUBMESSAGE_HEARTBEAT:
      dissect_HEARTBEAT(tvb, pinfo, offset, flags, encoding,
		  octets_to_next_header, rtps_submessage_tree, version, guid);
      break;

    case SUBMESSAGE_GAP:
      dissect_GAP(tvb, pinfo, offset, flags, encoding,
		  octets_to_next_header, rtps_submessage_tree, guid);
      break;

    case SUBMESSAGE_INFO_TS:
      dissect_INFO_TS(tvb, pinfo, offset, flags, encoding, octets_to_next_header, rtps_submessage_tree);
      break;

    case SUBMESSAGE_INFO_SRC:
      dissect_INFO_SRC(tvb, pinfo, offset, flags, encoding, octets_to_next_header, rtps_submessage_tree, version);
      break;

    case SUBMESSAGE_INFO_REPLY_IP4:
      dissect_INFO_REPLY_IP4(tvb, pinfo, offset, flags, encoding, octets_to_next_header, rtps_submessage_tree);
      break;

    case SUBMESSAGE_INFO_DST:
      dissect_INFO_DST(tvb, pinfo, offset, flags, encoding,
          octets_to_next_header, rtps_submessage_tree, version, dst_guid);
      break;

    case SUBMESSAGE_INFO_REPLY:
      dissect_INFO_REPLY(tvb, pinfo, offset, flags, encoding, octets_to_next_header, rtps_submessage_tree);
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
  proto_tree   *rtps_tree;
  guint8       majorRev;
  guint16      version, vendor_id;
  gboolean     is_ping;
  endpoint_guid guid;
  endpoint_guid *guid_copy;
  guint32 magic_number;
  gchar domain_id_str[RTPS_UNKNOWN_DOMAIN_ID_STR_LEN] = RTPS_UNKNOWN_DOMAIN_ID_STR;
  /* Check 'RTPS' signature:
   * A header is invalid if it has less than 16 octets
   */
  if (tvb_reported_length_remaining(tvb, offset) < 16)
    return FALSE;

  magic_number = tvb_get_ntohl(tvb, offset);
  if (magic_number != RTPX_MAGIC_NUMBER &&
      magic_number != RTPS_MAGIC_NUMBER) {
      return FALSE;
  }
  /* Distinguish between RTPS 1.x and 2.x here */
  majorRev = tvb_get_guint8(tvb,offset+4);
  if ((majorRev != 1) && (majorRev != 2))
    return FALSE;

  /* No fields have been set in GUID yet. */
  guid.fields_present = 0;

  col_set_str(pinfo->cinfo, COL_PROTOCOL, "RTPS");
  col_clear(pinfo->cinfo, COL_INFO);

  /* create display subtree for the protocol */
  ti = proto_tree_add_item(tree, proto_rtps, tvb, 0, -1, ENC_NA);
  rtps_tree = proto_item_add_subtree(ti, ett_rtps);

  /* magic */
  proto_tree_add_item(rtps_tree, hf_rtps_magic, tvb, 0, 4, ENC_NA | ENC_ASCII);

  /*  Protocol Version */
  version = rtps_util_add_protocol_version(rtps_tree, tvb, offset+4);

  /*  Vendor Id  */
  vendor_id = rtps_util_add_vendor_id(rtps_tree, tvb, offset+6);

  is_ping = rtps_is_ping(tvb, pinfo, offset+8);

  if (!is_ping) {
    if (version < 0x0200)
      rtps_util_add_guid_prefix_v1(rtps_tree, tvb, offset+8,
                        hf_rtps_guid_prefix_v1, hf_rtps_host_id, hf_rtps_app_id,
                        hf_rtps_app_id_instance_id, hf_rtps_app_id_app_kind, NULL);
    else
      rtps_util_add_guid_prefix_v2(rtps_tree, tvb, offset+8, hf_rtps_guid_prefix_src,
          hf_rtps_host_id, hf_rtps_app_id, hf_rtps_sm_instance_id, hf_rtps_guid_prefix);

    guid.host_id = tvb_get_ntohl(tvb, offset+8);
    guid.app_id = tvb_get_ntohl(tvb, offset+12);
    guid.instance_id = tvb_get_ntohl(tvb, offset+16);
    guid.fields_present = GUID_HAS_HOST_ID|GUID_HAS_APP_ID|GUID_HAS_INSTANCE_ID;
    /* If the packet uses TCP we need top store the participant GUID to get the domainId later
     * For that operation the member fields_present is not required and is not affected by
     * its changes.
     */
    guid_copy = (endpoint_guid*)wmem_memdup(pinfo->pool,
        (const void*)&guid, sizeof(endpoint_guid));
    p_add_proto_data(pinfo->pool, pinfo, proto_rtps,
        RTPS_TCPMAP_DOMAIN_ID_PROTODATA_KEY, (gpointer)guid_copy);
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
      /* If using TCP domainId cannot deduced from the port. It must be taken from the participant
       * discovery packets or Unknown.
       */
      domain_id = (pinfo->ptype == PT_TCP) ?
        get_domain_id_from_tcp_discovered_participants(discovered_tcp_participants, &guid) :
        ((pinfo->destport - PORT_BASE)/10) % 100;
      participant_idx = (pinfo->destport - PORT_BASE) / 1000;
      nature    = (pinfo->destport % 10);
    } else {
      domain_id = (pinfo->ptype == PT_TCP) ?
        get_domain_id_from_tcp_discovered_participants(discovered_tcp_participants, &guid) :
        (pinfo->destport - PORT_BASE) / 250;
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
    /* Used string for the domain participant to show Unknown if the domainId is not known when using TCP*/
    if (domain_id != RTPS_UNKNOWN_DOMAIN_ID_VAL) {
      snprintf(domain_id_str, RTPS_UNKNOWN_DOMAIN_ID_STR_LEN,
        "%"PRId32, domain_id);
    }
    if ((nature == PORT_METATRAFFIC_UNICAST) || (nature == PORT_USERTRAFFIC_UNICAST) ||
        (version < 0x0200)) {
      mapping_tree = proto_tree_add_subtree_format(rtps_tree, tvb, 0, 0,
                        ett_rtps_default_mapping, NULL, "Default port mapping: domainId=%s, "
                        "participantIdx=%d, nature=%s",
                        domain_id_str,
                        participant_idx,
                        val_to_str(nature, nature_type_vals, "%02x"));
    } else {
      mapping_tree = proto_tree_add_subtree_format(rtps_tree, tvb, 0, 0,
                        ett_rtps_default_mapping, NULL, "Default port mapping: %s, domainId=%s",
                        val_to_str(nature, nature_type_vals, "%02x"),
                        domain_id_str);
    }

    ti = proto_tree_add_uint(mapping_tree, hf_rtps_domain_id, tvb, 0, 0, domain_id);
    proto_item_set_generated(ti);
    if ((nature == PORT_METATRAFFIC_UNICAST) || (nature == PORT_USERTRAFFIC_UNICAST) ||
        (version < 0x0200)) {
      ti = proto_tree_add_uint(mapping_tree, hf_rtps_participant_idx, tvb, 0, 0, participant_idx);
      proto_item_set_generated(ti);
    }
    ti = proto_tree_add_uint(mapping_tree, hf_rtps_nature_type, tvb, 0, 0, nature);
    proto_item_set_generated(ti);
  }

  /* offset behind RTPS's Header (need to be set in case tree=NULL)*/
  offset += ((version < 0x0200) ? 16 : 20);

  dissect_rtps_submessages(tvb, offset, pinfo, rtps_tree, version, vendor_id, &guid);

  /* If TCP there's an extra OOB byte at the end of the message */
  /* TODO: What to do with it? */
  return TRUE;

}  /* dissect_rtps(...) */

void dissect_rtps_submessages(
    tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *rtps_tree,
    guint16 version, guint16 vendor_id, endpoint_guid *guid)
{
  guint8 submessageId, flags;
  int sub_hf;
  const value_string *sub_vals;
  proto_item *ti;
  proto_tree *rtps_submessage_tree;
  guint encoding;
  gint next_submsg, octets_to_next_header;
  endpoint_guid dst_guid;

  /* No fields have been set in GUID yet. */
  dst_guid.fields_present = 0;
  while (tvb_reported_length_remaining(tvb, offset) > 0) {
    submessageId = tvb_get_guint8(tvb, offset);

    if (version < 0x0200) {
      sub_hf = hf_rtps_sm_id;
      sub_vals = submessage_id_vals;
    } else {
      if ((submessageId & 0x80) && (vendor_id == RTPS_VENDOR_RTI_DDS)) {
        sub_hf = hf_rtps_sm_idv2;
        sub_vals = submessage_id_rti;
      } else {
        sub_hf = hf_rtps_sm_idv2;
        sub_vals = submessage_id_valsv2;
      }
    }

    col_append_sep_str(pinfo->cinfo, COL_INFO, ", ", val_to_str(submessageId, sub_vals, "Unknown[%02x]"));

    /* Creates the subtree 'Submessage: XXXX' */
    if (submessageId & 0x80) {
      if (vendor_id == RTPS_VENDOR_RTI_DDS) {
        ti = proto_tree_add_uint_format_value(rtps_tree, sub_hf, tvb, offset, 1, submessageId, "%s",
                val_to_str(submessageId, submessage_id_rti, "Vendor-specific (0x%02x)"));
      } else {
        ti = proto_tree_add_uint_format_value(rtps_tree, sub_hf, tvb, offset, 1,
                submessageId, "Vendor-specific (0x%02x)", submessageId);
      }
    } else {
      ti = proto_tree_add_uint(rtps_tree, sub_hf, tvb, offset, 1, submessageId);
    }

    rtps_submessage_tree = proto_item_add_subtree(ti, ett_rtps_submessage);

    /* Gets the flags */
    flags = tvb_get_guint8(tvb, offset + 1);

    /* Gets the E (Little endian) flag */
    encoding = ((flags & FLAG_E) != 0) ? ENC_LITTLE_ENDIAN : ENC_BIG_ENDIAN;

    /* Octets-to-next-header */
    octets_to_next_header = tvb_get_guint16(tvb, offset + 2, encoding);
    if ((octets_to_next_header == 0) && (version >= 0x0200)
        && (submessageId != SUBMESSAGE_PAD) && (submessageId != SUBMESSAGE_INFO_TS)) {
      octets_to_next_header = tvb_reported_length_remaining(tvb, offset + 4);
    }
    next_submsg = offset + octets_to_next_header + 4;

    /* Set length of this item */
    proto_item_set_len(ti, octets_to_next_header + 4);

    /* Now decode each single submessage
     * The offset passed to the dissectors points to the start of the
     * submessage (at the ID byte).
     */
    if (!dissect_rtps_submessage_v1(tvb, pinfo, offset, flags, encoding,
                                    submessageId, version, vendor_id,
                                    octets_to_next_header, rtps_submessage_tree,
                                    ti, guid, &dst_guid)) {
      if ((version < 0x0200) ||
          !dissect_rtps_submessage_v2(tvb, pinfo, offset, flags, encoding, submessageId,
                                      vendor_id, octets_to_next_header, rtps_submessage_tree,
                                      ti, guid, &dst_guid)) {
        proto_tree_add_uint(rtps_submessage_tree, hf_rtps_sm_flags,
                              tvb, offset + 1, 1, flags);
        proto_tree_add_uint(rtps_submessage_tree,
                                hf_rtps_sm_octets_to_next_header,
                                tvb, offset + 2, 2, octets_to_next_header);
      }
    }

     /* next submessage's offset */
     offset = next_submsg;
  }
}

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

static gboolean dissect_rtps_rtitcp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
  gint offset = 0;

  return dissect_rtps(tvb, pinfo, tree, offset);
}

static int dissect_simple_rtps(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
  gint offset = 0;

  if (dissect_rtps(tvb, pinfo, tree, offset) == FALSE)
    return 0;

  return tvb_captured_length(tvb);
}

void proto_register_rtps(void) {

  static hf_register_info hf[] = {

    { &hf_rtps_magic, {
        "Magic",
        "rtps.magic",
        FT_STRING,
        BASE_NONE,
        NULL,
        0,
        "RTPS magic",
        HFILL }
    },
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

    { &hf_rtps_domain_tag, {
        "domain_tag",
        "rtps.domain_tag",
        FT_STRINGZ,
        BASE_NONE,
        NULL,
        0,
        "Domain Tag ID",
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
    { &hf_rtps_guid_prefix_v1,
      { "guidPrefix", "rtps.guidPrefix_v1",
         FT_UINT64, BASE_HEX, NULL, 0,
         "GuidPrefix of the RTPS packet", HFILL }
    },

    { &hf_rtps_guid_prefix,
      { "guidPrefix", "rtps.guidPrefix",
         FT_BYTES, BASE_NONE, NULL, 0,
         "a generic guidPrefix that is transmitted inside the submessage (this is NOT the guidPrefix described in the packet header)", HFILL }
    },

    { &hf_rtps_guid_prefix_src,
      { "guidPrefix", "rtps.guidPrefix.src",
         FT_BYTES, BASE_NONE, NULL, 0,
         "the guidPrefix of the entity sending the sample", HFILL }
    },

    { &hf_rtps_guid_prefix_dst,
      { "guidPrefix", "rtps.guidPrefix.dst",
         FT_BYTES, BASE_NONE, NULL, 0,
         "the guidPrefix of the entity receiving the sample", HFILL }
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
    { &hf_rtps_sm_flags2, {
        "Flags",
        "rtps.sm.flags",
        FT_UINT16,
        BASE_HEX,
        NULL,
        0,
        "bitmask representing the flags associated with a submessage",
        HFILL }
    },

    /* octets to next header ---------------------------------------------- */
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
    { &hf_rtps_sm_guid_prefix_v1, {
        "guidPrefix",
        "rtps.sm.guidPrefix_v1",
        FT_UINT64,
        BASE_HEX,
        NULL,
        0,
        "a generic guidPrefix that is transmitted inside the submessage (this is NOT the guidPrefix described in the packet header)",
        HFILL }
    },

    { &hf_rtps_sm_guid_prefix, {
        "guidPrefix",
        "rtps.sm.guidPrefix",
        FT_BYTES,
        BASE_NONE,
        NULL,
        0,
        "a generic guidPrefix that is transmitted inside the submessage (this is NOT the guidPrefix described in the packet header)",
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
    { &hf_rtps_sm_instance_id_v1, {
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
    { &hf_rtps_sm_instance_id, {
        "instanceId",
        "rtps.sm.guidPrefix.instanceId",
        FT_UINT32,
        BASE_HEX,
        NULL,
        0,
        "instanceId component of the rtps.sm.guidPrefix",
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

    { &hf_rtps_parameter_id_inline_rti, {
        "Parameter Id", "rtps.param.id", FT_UINT16,
        BASE_HEX, VALS(parameter_id_inline_qos_rti), 0, NULL, HFILL }
    },

    { &hf_rtps_parameter_id_toc, {
        "parameterId",
        "rtps.param.id",
        FT_UINT16,
        BASE_HEX,
        VALS(parameter_id_toc_vals),
        0,
        "Parameter Id",
        HFILL }
    },

    { &hf_rtps_parameter_id_rti, {
        "parameterId",
        "rtps.param.id",
        FT_UINT16,
        BASE_HEX,
        VALS(parameter_id_rti_vals),
        0,
        "Parameter Id",
        HFILL }
    },

    { &hf_rtps_parameter_id_adl, {
        "parameterId",
        "rtps.param.id",
        FT_UINT16,
        BASE_HEX,
        VALS(parameter_id_adl_vals),
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

    { &hf_rtps_transportInfo_classId, {
      "classID",
        "rtps.transportInfo.classID",
        FT_INT32,
        BASE_DEC,
        NULL,
        0,
        "Class ID of transport",
        HFILL }
    },

    { &hf_rtps_transportInfo_messageSizeMax, {
      "messageSizeMax",
        "rtps.transportInfo.messageSizeMax",
        FT_INT32,
        BASE_DEC,
        NULL,
        0,
        "Maximum message size of transport",
        HFILL }
    },
    { &hf_rtps_coherent_set_start, {
        "Coherent set start",
        "rtps.coherent_set.start",
        FT_UINT64,
        BASE_DEC,
        NULL,
        0,
        "Start of a coherent set",
        HFILL }
    },

    { &hf_rtps_coherent_set_end, {
        "End of coherent set sequence",
        "rtps.coherent_set.end",
        FT_UINT64,
        BASE_DEC,
        NULL,
        0,
        "End of a coherent set",
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
    { &hf_rtps_param_content_filter_topic_name, {
        "contentFilterTopicName",
        "rtps.param.contentFilterTopicName",
        FT_STRINGZ,
        BASE_NONE,
        NULL,
        0,
        "Value of the content filter topic name as sent in a PID_CONTENT_FILTER_PROPERTY parameter",
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
    { &hf_rtps_param_filter_class_name, {
        "filterClassName",
        "rtps.param.filterClassName",
        FT_STRINGZ,
        BASE_NONE,
        NULL,
        0,
        "Value of the filter class name as sent in a PID_CONTENT_FILTER_PROPERTY parameter",
        HFILL }
    },

    { &hf_rtps_durability_service_cleanup_delay,
      { "Service Cleanup Delay", "rtps.durability.service_cleanup_delay",
        FT_ABSOLUTE_TIME, ABSOLUTE_TIME_UTC, NULL, 0,
        "Time using the RTPS time_t standard format", HFILL }
    },

    { &hf_rtps_liveliness_lease_duration,
      { "Lease Duration", "rtps.liveliness.lease_duration",
        FT_ABSOLUTE_TIME, ABSOLUTE_TIME_UTC, NULL, 0,
        "Time using the RTPS time_t standard format", HFILL }
    },

    { &hf_rtps_participant_lease_duration,
      { "Duration", "rtps.participant_lease_duration",
        FT_ABSOLUTE_TIME, ABSOLUTE_TIME_UTC, NULL, 0,
        "Time using the RTPS time_t standard format", HFILL }
    },

    { &hf_rtps_time_based_filter_minimum_separation,
      { "Minimum Separation", "rtps.time_based_filter.minimum_separation",
        FT_ABSOLUTE_TIME, ABSOLUTE_TIME_UTC, NULL, 0,
        "Time using the RTPS time_t standard format", HFILL }
    },

    { &hf_rtps_reliability_max_blocking_time,
      { "Max Blocking Time", "rtps.reliability.max_blocking_time",
        FT_ABSOLUTE_TIME, ABSOLUTE_TIME_UTC, NULL, 0,
        "Time using the RTPS time_t standard format", HFILL }
    },

    { &hf_rtps_deadline_period,
      { "Period", "rtps.deadline_period",
        FT_ABSOLUTE_TIME, ABSOLUTE_TIME_UTC, NULL, 0,
        "Time using the RTPS time_t standard format", HFILL }
    },

    { &hf_rtps_latency_budget_duration,
      { "Duration", "rtps.latency_budget.duration",
        FT_ABSOLUTE_TIME, ABSOLUTE_TIME_UTC, NULL, 0,
        "Time using the RTPS time_t standard format", HFILL }
    },

    { &hf_rtps_lifespan_duration,
      { "Duration", "rtps.lifespan",
        FT_ABSOLUTE_TIME, ABSOLUTE_TIME_UTC, NULL, 0,
        "Time using the RTPS time_t standard format", HFILL }
    },

    { &hf_rtps_persistence,
      { "Persistence", "rtps.persistence",
        FT_ABSOLUTE_TIME, ABSOLUTE_TIME_UTC, NULL, 0,
        "Time using the RTPS time_t standard format", HFILL }
    },

    { &hf_rtps_info_ts_timestamp,
      { "Timestamp", "rtps.info_ts.timestamp",
        FT_ABSOLUTE_TIME, ABSOLUTE_TIME_UTC, NULL, 0,
        "Time using the RTPS time_t standard format", HFILL }
    },

    { &hf_rtps_locator_kind,
      { "Kind", "rtps.locator.kind",
        FT_UINT32, BASE_HEX, VALS(rtps_locator_kind_vals), 0,
        NULL, HFILL }
    },

    { &hf_rtps_locator_port,
      { "Port", "rtps.locator.port",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }
    },
#if 0
    { &hf_rtps_logical_port,
      { "RTPS Logical Port", "rtps.locator.port",
        FT_INT32, BASE_DEC, NULL, 0,
        NULL, HFILL }
    },
#endif
    { &hf_rtps_locator_public_address_port,
      { "Public Address Port", "rtps.locator.public_address_port",
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

    { &hf_rtps_acknack_count,
      { "Count", "rtps.acknack.count",
        FT_INT32, BASE_DEC, NULL, 0,
        NULL, HFILL }
    },

    { &hf_rtps_param_app_ack_virtual_writer_count,
      { "virtualWriterCount", "rtps.app_ack.virtual_writer_count",
        FT_INT32, BASE_DEC, NULL, 0,
        NULL, HFILL }
    },

    { &hf_rtps_param_app_ack_count,
      { "count", "rtps.app_ack.count",
        FT_INT32, BASE_DEC, NULL, 0,
        NULL, HFILL }
    },

    { &hf_rtps_param_app_ack_conf_virtual_writer_count,
      { "virtualWriterCount", "rtps.app_ack_conf.virtual_writer_count",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }
    },

    { &hf_rtps_param_app_ack_conf_count,
      { "count", "rtps.app_ack_conf.count",
        FT_INT32, BASE_DEC, NULL, 0,
        NULL, HFILL }
    },

    { &hf_rtps_param_app_ack_interval_payload_length,
      { "intervalPayloadLength", "rtps.app_ack.interval_payload_length",
        FT_INT16, BASE_DEC, NULL, 0,
        NULL, HFILL }
    },

    { &hf_rtps_param_app_ack_interval_flags,
      { "intervalFlags", "rtps.app_ack.interval_flags",
        FT_INT16, BASE_DEC, NULL, 0,
        NULL, HFILL }
    },

    { &hf_rtps_param_app_ack_interval_count,
      { "intervalCount", "rtps.app_ack.interval_count",
        FT_INT16, BASE_DEC, NULL, 0,
        NULL, HFILL }
    },

    { &hf_rtps_param_app_ack_octets_to_next_virtual_writer,
      { "octetsToNextVirtualWriter", "rtps.app_ack.octets_to_next_virtual_writer",
        FT_INT16, BASE_DEC, NULL, 0,
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

    { &hf_rtps_direct_communication,
      { "Direct Communication", "rtps.direct_communication",
        FT_BOOLEAN, 8, TFS(&tfs_true_false), 0,
        NULL, HFILL }
    },

    { &hf_rtps_expects_ack,
      { "expectsAck", "rtps.expects_ack",
        FT_BOOLEAN, 8, TFS(&tfs_true_false), 0,
        NULL, HFILL }
    },

    { &hf_rtps_expects_virtual_heartbeat,
      { "expectsVirtualHB", "rtps.expects_virtual_heartbeat",
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

    /* Parameter / NtpTime ------------------------------------------------- */
    { &hf_rtps_param_timestamp_sec, {
      "seconds", "rtps.param.ntpTime.sec",
        FT_INT32, BASE_DEC, NULL, 0,
        "The 'second' component of an RTPS time_t",
        HFILL }
    },

    { &hf_rtps_param_timestamp_fraction, {
      "fraction", "rtps.param.ntpTime.fraction",
        FT_UINT32, BASE_DEC, NULL, 0,
        "The 'fraction' component of an RTPS time_t",
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

    { &hf_rtps_param_peer_host_epoch,
      { "Peer Host Epoch", "rtps.param.peer_host_epoch",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }
    },

    { &hf_rtps_param_endpoint_property_change_epoch,
      { "Endpoint Property Change Epoch", "rtps.param.endpoint_property_change_epoch",
        FT_INT64, BASE_DEC, NULL, 0, NULL, HFILL }
    },

    { &hf_rtps_param_entity_name,
      { "entityName", "rtps.param.entityName",
        FT_STRINGZ, BASE_NONE, NULL, 0,
        "String representing the name of the entity addressed by the submessage",
        HFILL }
    },

    { &hf_rtps_param_role_name,
      { "roleName", "rtps.param.roleName",
        FT_STRINGZ, BASE_NONE, NULL, 0,
        "String representing the role name of the entity addressed by the submessage",
        HFILL }
    },

    { &hf_rtps_disable_positive_ack,
      { "disablePositiveAcks", "rtps.disable_positive_ack",
        FT_BOOLEAN, 8, TFS(&tfs_true_false), 0,
        NULL, HFILL }
    },

    { &hf_rtps_participant_guid_v1,
      { "Participant GUID", "rtps.param.participant_guid_v1",
        FT_UINT64, BASE_HEX, NULL, 0,
        NULL, HFILL }
    },

    { &hf_rtps_participant_guid,
      { "Participant GUID", "rtps.param.participant_guid",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }
    },

    { &hf_rtps_group_guid_v1,
      { "Group GUID", "rtps.param.group_guid_v1",
        FT_UINT64, BASE_HEX, NULL, 0,
        NULL, HFILL }
    },

    { &hf_rtps_group_guid,
      { "Group GUID", "rtps.param.group_guid",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }
    },

    { &hf_rtps_endpoint_guid,
      { "Endpoint GUID", "rtps.param.endpoint_guid",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }
    },

    { &hf_rtps_param_host_id,
      { "hostId", "rtps.param.guid.hostId",
        FT_UINT32, BASE_HEX, NULL, 0,
        NULL, HFILL }
    },

    { &hf_rtps_param_app_id,
      { "appId", "rtps.param.guid.appId",
        FT_UINT32, BASE_HEX, NULL, 0,
        NULL, HFILL }
    },

    { &hf_rtps_param_instance_id_v1,
      { "instanceId", "rtps.param.guid.instanceId",
        FT_UINT24, BASE_HEX, NULL, 0,
        NULL, HFILL }
    },

    { &hf_rtps_param_instance_id,
      { "instanceId", "rtps.param.guid.instanceId",
        FT_UINT32, BASE_HEX, NULL, 0,
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

    { &hf_rtps_param_extended_pid_length,
      { "Extended Length", "rtps.param.extended_pid_length",
        FT_UINT32, BASE_HEX, NULL, 0,
        NULL, HFILL }
    },

    { &hf_rtps_param_extended_parameter,
      { "Extended Parameter", "rtps.param.extended_parameter",
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

    { &hf_rtps_virtual_heartbeat_count,
      { "Count", "rtps.virtual_heartbeat.count",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }
    },

    { &hf_rtps_virtual_heartbeat_num_virtual_guids,
      { "numVirtualGUIDs", "rtps.virtual_heartbeat.num_virtual_guids",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }
    },

    { &hf_rtps_virtual_heartbeat_num_writers,
      { "numWriters", "rtps.virtual_heartbeat.num_writers",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }
    },

    { &hf_rtps_data_serialize_data, {
        "serializedData", "rtps.data.serialize_data",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }
    },

    { &hf_rtps_parameter_data, {
        "parameterData", "rtps.parameter_data",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }
    },

    { &hf_rtps_data_batch_timestamp,
      { "Timestamp", "rtps.data_batch.timestamp",
        FT_ABSOLUTE_TIME, ABSOLUTE_TIME_UTC, NULL, 0,
        "Time using the RTPS time_t standard format", HFILL }
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
      { "bitmapBase", "rtps.fragment_number.base64",
        FT_UINT64, BASE_DEC, NULL, 0,
        NULL, HFILL }
    },

    { &hf_rtps_fragment_number_base,
      { "bitmapBase", "rtps.fragment_number.base32",
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

    { &hf_rtps_acknack_analysis,
      { "Acknack Analysis", "rtps.sm.acknack_analysis",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }
    },

    { &hf_rtps_param_partition_num,
      { "Number of partition names", "rtps.param.partition_num",
        FT_INT32, BASE_DEC, NULL, 0,
        NULL, HFILL }
    },

    { &hf_rtps_param_expression_parameters_num,
      { "Number of expression params", "rtps.param.expression_parameters_num",
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

    { &hf_rtps_param_expression_parameters,
      { "expressionParameters", "rtps.param.expression_parameters",
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

    { &hf_rtps_param_builtin_endpoint_set_flags,
      { "Flags", "rtps.param.builtin_endpoint_set",
        FT_UINT32, BASE_HEX, NULL, 0,
        "bitmask representing the flags in PID_BUILTIN_ENDPOINT_SET",
        HFILL }
    },

    { &hf_rtps_param_vendor_builtin_endpoint_set_flags,
      { "Flags", "rtps.param.vendor_builtin_endpoint_set",
        FT_UINT32, BASE_HEX, NULL, 0,
        "bitmask representing the flags in PID_VENDOR_BUILTIN_ENDPOINT_SET",
        HFILL }
    },

    { &hf_rtps_param_endpoint_security_attributes,
      { "Flags", "rtps.param.endpoint_security_attributes",
        FT_UINT32, BASE_HEX, NULL, 0,
        "bitmask representing the flags in PID_ENDPOINT_SECURITY_ATTRIBUTES",
        HFILL }
    },

    { &hf_rtps_param_plugin_promiscuity_kind, {
        "promiscuityKind", "rtps.param.plugin_promiscuity_kind",
        FT_UINT32, BASE_HEX, VALS(plugin_promiscuity_kind_vals), 0, NULL, HFILL }
    },

    { &hf_rtps_param_service_kind, {
        "serviceKind", "rtps.param.service_kind",
        FT_UINT32, BASE_HEX, VALS(service_kind_vals), 0, NULL, HFILL }
    },

    { &hf_rtps_param_data_representation,{
        "Data Representation Kind", "rtps.param.data_representation",
        FT_UINT16, BASE_DEC, VALS(data_representation_kind_vals), 0, NULL, HFILL }
    },

    { &hf_rtps_param_type_consistency_kind, {
        "Type Consistency Kind", "rtps.param.type_consistency_kind",
        FT_UINT16, BASE_HEX, VALS(type_consistency_kind_vals), 0, NULL, HFILL }
    },

    { &hf_rtps_param_ignore_sequence_bounds, {
        "Ignore Sequence Bounds", "rtps.param.ignore_sequence_bounds",
        FT_BOOLEAN, BASE_NONE, NULL, 0, NULL, HFILL }
    },

    { &hf_rtps_param_ignore_string_bounds, {
        "Ignore String Bounds", "rtps.param.ignore_string_bounds",
        FT_BOOLEAN, BASE_NONE, NULL, 0, NULL, HFILL }
    },

    { &hf_rtps_param_ignore_member_names, {
        "Ignore Member Names", "rtps.param.ignore_member_names",
        FT_BOOLEAN, BASE_NONE, NULL, 0, NULL, HFILL }
    },

    { &hf_rtps_param_prevent_type_widening, {
         "Prevent Type Widening", "rtps.param.prevent_type_widening",
        FT_BOOLEAN, BASE_NONE, NULL, 0, NULL, HFILL }
    },

    { &hf_rtps_param_force_type_validation, {
         "Force Type Validation", "rtps.param.force_type_validation",
        FT_BOOLEAN, BASE_NONE, NULL, 0, NULL, HFILL }
    },

    { &hf_rtps_param_ignore_enum_literal_names, {
        "Ignore Enum Literal Names", "rtps.param.ignore_enum_literal_names",
        FT_BOOLEAN, BASE_NONE, NULL, 0, NULL, HFILL }
    },

    { &hf_rtps_param_acknowledgment_kind, {
        "Acknowledgment Kind", "rtps.param.acknowledgment_kind",
        FT_UINT32, BASE_HEX, VALS(acknowledgement_kind_vals), 0, NULL, HFILL }
    },

    /* Finally the raw issue data ------------------------------------------ */
    { &hf_rtps_issue_data, {
        "serializedData", "rtps.issueData",
        FT_BYTES, BASE_NONE, NULL, 0, "The user data transferred in a ISSUE submessage", HFILL }
    },

    { &hf_rtps_param_product_version_major, {
        "Major", "rtps.param.product_version.major",
        FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }
    },

    { &hf_rtps_param_product_version_minor, {
        "Minor", "rtps.param.product_version.minor",
        FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }
    },

    { &hf_rtps_param_product_version_release, {
        "Release", "rtps.param.product_version.release",
        FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }
    },

    { &hf_rtps_param_product_version_release_as_char, {
        "Release", "rtps.param.product_version.release_string",
        FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }
    },

    { &hf_rtps_param_product_version_revision, {
        "Revision", "rtps.param.product_version.revision",
        FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }
    },

    { &hf_rtps_encapsulation_id, {
        "encapsulation id", "rtps.encapsulation_id",
        FT_UINT16, BASE_HEX, VALS(encapsulation_id_vals), 0, NULL, HFILL }
    },

    { &hf_rtps_encapsulation_kind, {
        "kind", "rtps.encapsulation_kind",
        FT_UINT16, BASE_HEX, VALS(participant_message_data_kind), 0, NULL, HFILL }
    },

    { &hf_rtps_octets_to_inline_qos, {
        "Octets to inline QoS", "rtps.octets_to_inline_qos",
        FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL }
    },

    { &hf_rtps_filter_signature, {
        "filterSignature", "rtps.filter_signature",
        FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL }
    },

    { &hf_rtps_bitmap, {
        "bitmap", "rtps.bitmap",
        FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL }
    },

    { &hf_rtps_property_name, {
        "Property Name", "rtps.property_name",
        FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }
    },

    { &hf_rtps_property_value, {
        "Value", "rtps.property_value",
        FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }
    },

    { &hf_rtps_union, {
        "union", "rtps.union",
        FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }
    },

    { &hf_rtps_union_case, {
        "case", "rtps.union_case",
        FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }
    },

    { &hf_rtps_struct, {
        "struct", "rtps.struct",
        FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }
    },

    { &hf_rtps_member_name, {
        "member_name", "rtps.member_name",
        FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }
    },

    { &hf_rtps_sequence, {
        "sequence", "rtps.sequence",
        FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }
    },

    { &hf_rtps_array, {
        "array", "rtps.array",
        FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }
    },

    { &hf_rtps_bitfield, {
        "bitfield", "rtps.bitfield",
        FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }
    },

    { &hf_rtps_datatype, {
        "datatype", "rtps.datatype",
        FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }
    },

    { &hf_rtps_sequence_size, {
        "sequenceSize", "rtps.sequence_size",
        FT_UINT32, BASE_DEC|BASE_UNIT_STRING, &units_octet_octets, 0, NULL, HFILL }
    },

    { &hf_rtps_guid, {
        "guid", "rtps.guid",
        FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL }
    },

    { &hf_rtps_heartbeat_count, {
        "count", "rtps.heartbeat_count",
        FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }
    },

    { &hf_rtps_encapsulation_options, {
        "Encapsulation options", "rtps.encapsulation_options",
        FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL }
    },

    { &hf_rtps_serialized_key, {
        "serializedKey", "rtps.serialized_key",
        FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL }
    },

    { &hf_rtps_serialized_data, {
        "serializedData", "rtps.serialized_data",
        FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL }
    },

    { &hf_rtps_sm_rti_crc_number, {
        "RTPS Message Length", "rtps.sm.rti_crc.message_length",
        FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }
    },

    { &hf_rtps_sm_rti_crc_result, {
        "CRC", "rtps.sm.rti_crc",
        FT_UINT32, BASE_HEX, NULL, 0, NULL, HFILL }
    },

    /* Flag bits */
    { &hf_rtps_flag_reserved80, {
        "Reserved", "rtps.flag.reserved",
        FT_BOOLEAN, 8, TFS(&tfs_set_notset), 0x80, NULL, HFILL }
    },
    { &hf_rtps_flag_reserved40, {
        "Reserved", "rtps.flag.reserved",
        FT_BOOLEAN, 8, TFS(&tfs_set_notset), 0x40, NULL, HFILL }
    },
    { &hf_rtps_flag_reserved20, {
        "Reserved", "rtps.flag.reserved",
        FT_BOOLEAN, 8, TFS(&tfs_set_notset), 0x20, NULL, HFILL }
    },
    { &hf_rtps_flag_reserved10, {
        "Reserved", "rtps.flag.reserved",
        FT_BOOLEAN, 8, TFS(&tfs_set_notset), 0x10, NULL, HFILL }
    },
    { &hf_rtps_flag_reserved08, {
        "Reserved", "rtps.flag.reserved",
        FT_BOOLEAN, 8, TFS(&tfs_set_notset), 0x08, NULL, HFILL }
    },
    { &hf_rtps_flag_reserved04, {
        "Reserved", "rtps.flag.reserved",
        FT_BOOLEAN, 8, TFS(&tfs_set_notset), 0x04, NULL, HFILL }
    },
    { &hf_rtps_flag_reserved02, {
        "Reserved", "rtps.flag.reserved",
        FT_BOOLEAN, 8, TFS(&tfs_set_notset), 0x02, NULL, HFILL }
    },
    { &hf_rtps_flag_reserved8000, {
        "Reserved", "rtps.flag.reserved",
        FT_BOOLEAN, 16, TFS(&tfs_set_notset), 0x8000, NULL, HFILL }
    },
    { &hf_rtps_flag_reserved4000, {
        "Reserved", "rtps.flag.reserved",
        FT_BOOLEAN, 16, TFS(&tfs_set_notset), 0x4000, NULL, HFILL }
    },
    { &hf_rtps_flag_reserved2000, {
        "Reserved", "rtps.flag.reserved",
        FT_BOOLEAN, 16, TFS(&tfs_set_notset), 0x2000, NULL, HFILL }
    },
    { &hf_rtps_flag_reserved1000, {
        "Reserved", "rtps.flag.reserved",
        FT_BOOLEAN, 16, TFS(&tfs_set_notset), 0x1000, NULL, HFILL }
    },
    { &hf_rtps_flag_reserved0800, {
        "Reserved", "rtps.flag.reserved",
        FT_BOOLEAN, 16, TFS(&tfs_set_notset), 0x0800, NULL, HFILL }
    },
    { &hf_rtps_flag_reserved0400, {
        "Reserved", "rtps.flag.reserved",
        FT_BOOLEAN, 16, TFS(&tfs_set_notset), 0x0400, NULL, HFILL }
    },
    { &hf_rtps_flag_reserved0200, {
        "Reserved", "rtps.flag.reserved",
        FT_BOOLEAN, 16, TFS(&tfs_set_notset), 0x0200, NULL, HFILL }
    },
    { &hf_rtps_flag_reserved0100, {
        "Reserved", "rtps.flag.reserved",
        FT_BOOLEAN, 16, TFS(&tfs_set_notset), 0x0100, NULL, HFILL }
    },
    { &hf_rtps_flag_reserved0080, {
        "Reserved", "rtps.flag.reserved",
        FT_BOOLEAN, 16, TFS(&tfs_set_notset), 0x0080, NULL, HFILL }
    },
    { &hf_rtps_flag_reserved0040, {
        "Reserved", "rtps.flag.reserved",
        FT_BOOLEAN, 16, TFS(&tfs_set_notset), 0x0040, NULL, HFILL }
    },
    { &hf_rtps_flag_builtin_endpoint_set_reserved, {
        "Reserved", "rtps.flag.reserved",
        FT_BOOLEAN, 32, TFS(&tfs_set_notset), 0x0000F000, NULL, HFILL }
    },
    { &hf_rtps_flag_unregister, {
        "Unregister flag", "rtps.flag.unregister",
        FT_BOOLEAN, 8, TFS(&tfs_set_notset), 0x20, NULL, HFILL }
    },
    { &hf_rtps_flag_inline_qos_v1, {
        "Inline QoS", "rtps.flag.inline_qos",
        FT_BOOLEAN, 8, TFS(&tfs_set_notset), 0x10, NULL, HFILL }
    },
    { &hf_rtps_flag_hash_key, {
        "Hash key flag", "rtps.flag.hash_key",
        FT_BOOLEAN, 8, TFS(&tfs_set_notset), 0x08, NULL, HFILL }
    },
    { &hf_rtps_flag_hash_key_rti, {
        "Hash key flag", "rtps.flag.hash_key",
        FT_BOOLEAN, 8, TFS(&tfs_set_notset), 0x04, NULL, HFILL }
    },
    { &hf_rtps_flag_alive, {
        "Alive flag", "rtps.flag.alive",
        FT_BOOLEAN, 8, TFS(&tfs_set_notset), 0x04, NULL, HFILL }
    },
    { &hf_rtps_flag_data_present_v1, {
        "Data present", "rtps.flag.data_present",
        FT_BOOLEAN, 8, TFS(&tfs_set_notset), 0x02, NULL, HFILL }
    },
    { &hf_rtps_flag_multisubmessage, {
        "Multi-submessage", "rtps.flag.multisubmessage",
        FT_BOOLEAN, 8, TFS(&tfs_set_notset), 0x02, NULL, HFILL }
    },
    { &hf_rtps_flag_endianness, {
        "Endianness bit", "rtps.flag.endianness",
        FT_BOOLEAN, 8, TFS(&tfs_set_notset), 0x01, NULL, HFILL }
    },
    { &hf_rtps_flag_inline_qos_v2, {
        "Inline QoS", "rtps.flag.inline_qos",
        FT_BOOLEAN, 8, TFS(&tfs_set_notset), 0x02, NULL, HFILL }
    },
    { &hf_rtps_flag_data_present_v2, {
        "Data present", "rtps.flag.data_present",
        FT_BOOLEAN, 8, TFS(&tfs_set_notset), 0x04, NULL, HFILL }
    },
    { &hf_rtps_flag_status_info, {
        "Status info flag", "rtps.flag.status_info",
        FT_BOOLEAN, 8, TFS(&tfs_set_notset), 0x10, NULL, HFILL }
    },
    { &hf_rtps_flag_final, {
        "Final flag", "rtps.flag.final",
        FT_BOOLEAN, 8, TFS(&tfs_set_notset), 0x02, NULL, HFILL }
    },
    { &hf_rtps_flag_liveliness, {
        "Liveliness flag", "rtps.flag.liveliness",
        FT_BOOLEAN, 8, TFS(&tfs_set_notset), 0x04, NULL, HFILL }
    },
    { &hf_rtps_flag_multicast, {
        "Multicast flag", "rtps.flag.multicast",
        FT_BOOLEAN, 8, TFS(&tfs_set_notset), 0x02, NULL, HFILL }
    },
    { &hf_rtps_flag_data_serialized_key, {
        "Serialized Key", "rtps.flag.data.serialized_key",
        FT_BOOLEAN, 8, TFS(&tfs_set_notset), 0x08, NULL, HFILL }
    },
    { &hf_rtps_flag_data_frag_serialized_key, {
        "Serialized Key", "rtps.flag.data_frag.serialized_key",
        FT_BOOLEAN, 8, TFS(&tfs_set_notset), 0x04, NULL, HFILL }
    },
    { &hf_rtps_flag_timestamp, {
        "Timestamp flag", "rtps.flag.timestamp",
        FT_BOOLEAN, 8, TFS(&tfs_set_notset), 0x02, NULL, HFILL }
    },
    { &hf_rtps_flag_no_virtual_guids, {
        "No virtual GUIDs flag", "rtps.flag.no_virtual_guids",
        FT_BOOLEAN, 8, TFS(&tfs_set_notset), 0x08, NULL, HFILL }
    },
    { &hf_rtps_flag_multiple_writers, {
        "Multiple writers flag", "rtps.flag.multiple_writers",
        FT_BOOLEAN, 8, TFS(&tfs_set_notset), 0x04, NULL, HFILL }
    },
    { &hf_rtps_flag_multiple_virtual_guids, {
        "Multiple virtual GUIDs flag", "rtps.flag.multiple_virtual_guids",
        FT_BOOLEAN, 8, TFS(&tfs_set_notset), 0x02, NULL, HFILL }
    },
    { &hf_rtps_flag_serialize_key16, {
        "Serialized Key", "rtps.flag.serialize_key",
        FT_BOOLEAN, 16, TFS(&tfs_set_notset), 0x0020, NULL, HFILL }
    },
    { &hf_rtps_flag_invalid_sample, {
        "Invalid sample", "rtps.flag.invalid_sample",
        FT_BOOLEAN, 16, TFS(&tfs_set_notset), 0x0010, NULL, HFILL }
    },
    { &hf_rtps_flag_data_present16, {
        "Data present", "rtps.flag.data_present",
        FT_BOOLEAN, 16, TFS(&tfs_set_notset), 0x0008, NULL, HFILL }
    },
    { &hf_rtps_flag_offsetsn_present, {
        "OffsetSN present", "rtps.flag.offsetsn_present",
        FT_BOOLEAN, 16, TFS(&tfs_set_notset), 0x0004, NULL, HFILL }
    },
    { &hf_rtps_flag_inline_qos16_v2, {
        "Inline QoS", "rtps.flag.inline_qos",
        FT_BOOLEAN, 16, TFS(&tfs_set_notset), 0x0002, NULL, HFILL }
    },
    { &hf_rtps_flag_timestamp_present, {
        "Timestamp present", "rtps.flag.timestamp_present",
        FT_BOOLEAN, 16, TFS(&tfs_set_notset), 0x0001, NULL, HFILL }
    },
    { &hf_rtps_param_status_info_flags,
      { "Flags", "rtps.param.status_info",
        FT_UINT32, BASE_HEX, NULL, 0, "bitmask representing the flags in PID_STATUS_INFO", HFILL }
    },
    { &hf_rtps_flag_unregistered, {
        "Unregistered", "rtps.flag.unregistered",
        FT_BOOLEAN, 8, TFS(&tfs_set_notset), 0x02, NULL, HFILL }
    },
    { &hf_rtps_flag_disposed, {
        "Disposed", "rtps.flag.undisposed",
        FT_BOOLEAN, 8, TFS(&tfs_set_notset), 0x01, NULL, HFILL }
    },
    { &hf_rtps_flag_participant_announcer, {
        "Participant Announcer", "rtps.flag.participant_announcer",
        FT_BOOLEAN, 32, TFS(&tfs_set_notset), 0x00000001, NULL, HFILL }
    },
    { &hf_rtps_flag_participant_detector, {
        "Participant Detector", "rtps.flag.participant_detector",
        FT_BOOLEAN, 32, TFS(&tfs_set_notset), 0x00000002, NULL, HFILL }
    },
    { &hf_rtps_flag_publication_announcer, {
        "Publication Announcer", "rtps.flag.publication_announcer",
        FT_BOOLEAN, 32, TFS(&tfs_set_notset), 0x00000004, NULL, HFILL }
    },
    { &hf_rtps_flag_publication_detector, {
        "Publication Detector", "rtps.flag.publication_detector",
        FT_BOOLEAN, 32, TFS(&tfs_set_notset), 0x00000008, NULL, HFILL }
    },
    { &hf_rtps_flag_subscription_announcer, {
        "Subscription Announcer", "rtps.flag.subscription_announcer",
        FT_BOOLEAN, 32, TFS(&tfs_set_notset), 0x00000010, NULL, HFILL }
    },
    { &hf_rtps_flag_subscription_detector, {
        "Subscription Detector", "rtps.flag.subscription_detector",
        FT_BOOLEAN, 32, TFS(&tfs_set_notset), 0x00000020, NULL, HFILL }
    },
    { &hf_rtps_flag_participant_proxy_announcer, {
        "Participant Proxy Announcer", "rtps.flag.participant_proxy_announcer",
        FT_BOOLEAN, 32, TFS(&tfs_set_notset), 0x00000040, NULL, HFILL }
    },
    { &hf_rtps_flag_participant_proxy_detector, {
        "Participant Proxy Detector", "rtps.flag.participant_proxy_detector",
        FT_BOOLEAN, 32, TFS(&tfs_set_notset), 0x00000080, NULL, HFILL }
    },
    { &hf_rtps_flag_participant_state_announcer, {
        "Participant State Announcer", "rtps.flag.participant_state_announcer",
        FT_BOOLEAN, 32, TFS(&tfs_set_notset), 0x00000100, NULL, HFILL }
    },
    { &hf_rtps_flag_participant_state_detector, {
        "Participant State Detector", "rtps.flag.participant_state_detector",
        FT_BOOLEAN, 32, TFS(&tfs_set_notset), 0x00000200, NULL, HFILL }
    },
    { &hf_rtps_flag_participant_message_datawriter, {
        "Participant Message DataWriter", "rtps.flag.participant_message_datawriter",
        FT_BOOLEAN, 32, TFS(&tfs_set_notset), 0x00000400, NULL, HFILL }
    },
    { &hf_rtps_flag_participant_message_datareader, {
        "Participant Message DataReader", "rtps.flag.participant_message_datareader",
        FT_BOOLEAN, 32, TFS(&tfs_set_notset), 0x00000800, NULL, HFILL }
    },
    { &hf_rtps_flag_secure_publication_writer, {
        "Secure Publication Writer", "rtps.flag.secure_publication_writer",
        FT_BOOLEAN, 32, TFS(&tfs_set_notset), 0x00010000, NULL, HFILL }
    },
    { &hf_rtps_flag_secure_publication_reader, {
        "Secure Publication Reader", "rtps.flag.secure_publication_reader",
        FT_BOOLEAN, 32, TFS(&tfs_set_notset), 0x00020000, NULL, HFILL }
    },
    { &hf_rtps_flag_secure_subscription_writer, {
        "Secure Subscription Writer", "rtps.flag.secure_subscription_writer",
        FT_BOOLEAN, 32, TFS(&tfs_set_notset), 0x00040000, NULL, HFILL }
    },
    { &hf_rtps_flag_secure_subscription_reader, {
        "Secure Subscription Reader", "rtps.flag.secure_subscription_reader",
        FT_BOOLEAN, 32, TFS(&tfs_set_notset), 0x00080000, NULL, HFILL }
    },
    { &hf_rtps_flag_secure_participant_message_writer, {
        "Secure Participant Message Writer", "rtps.flag.secure_participant_message_writer",
        FT_BOOLEAN, 32, TFS(&tfs_set_notset), 0x00100000, NULL, HFILL }
    },
    { &hf_rtps_flag_secure_participant_message_reader, {
        "Secure Participant Message Reader", "rtps.flag.secure_participant_message_reader",
        FT_BOOLEAN, 32, TFS(&tfs_set_notset), 0x00200000, NULL, HFILL }
    },
    { &hf_rtps_flag_participant_stateless_message_writer, {
        "Participant Stateless Message Writer", "rtps.flag.participant_stateless_message_writer",
        FT_BOOLEAN, 32, TFS(&tfs_set_notset), 0x00400000, NULL, HFILL }
    },
    { &hf_rtps_flag_participant_stateless_message_reader, {
        "Participant Stateless Message Reader", "rtps.flag.participant_stateless_message_reader",
        FT_BOOLEAN, 32, TFS(&tfs_set_notset), 0x00800000, NULL, HFILL }
    },
    { &hf_rtps_flag_secure_participant_volatile_message_writer,{
        "Secure Participant Volatile Message Writer", "rtps.flag.secure_participant_volatile_message_writer",
        FT_BOOLEAN, 32, TFS(&tfs_set_notset), 0x01000000, NULL, HFILL }
    },
    { &hf_rtps_flag_secure_participant_volatile_message_reader,{
        "Secure Participant Volatile Message Reader", "rtps.flag.secure_participant_volatile_message_reader",
        FT_BOOLEAN, 32, TFS(&tfs_set_notset), 0x02000000, NULL, HFILL }
    },
    { &hf_rtps_flag_participant_secure_writer,{
        "Participant Secure Writer", "rtps.flag.participant_secure_writer",
        FT_BOOLEAN, 32, TFS(&tfs_set_notset), 0x04000000, NULL, HFILL }
    },
    { &hf_rtps_flag_participant_secure_reader,{
        "Participant Secure Reader", "rtps.flag.participant_secure_reader",
        FT_BOOLEAN, 32, TFS(&tfs_set_notset), 0x08000000, NULL, HFILL }
    },
    { &hf_rtps_type_object_type_id_disc,
          { "TypeId (_d)", "rtps.type_object.type_id.discr",
            FT_INT16, BASE_DEC, 0x0, 0,
            NULL, HFILL }
    },
    { &hf_rtps_type_object_primitive_type_id,
      { "Type Id", "rtps.type_object.primitive_type_id",
        FT_UINT16, BASE_HEX, VALS(type_object_kind), 0,
        NULL, HFILL }
    },
    { &hf_rtps_type_object_base_primitive_type_id,
      { "Base Id", "rtps.type_object.base_primitive_type_id",
        FT_UINT16, BASE_HEX, VALS(type_object_kind), 0,
        NULL, HFILL }
    },
    { &hf_rtps_type_object_type_id,
      { "Type Id", "rtps.type_object.type_id",
        FT_UINT64, BASE_HEX, 0x0, 0,
        NULL, HFILL }
    },
    { &hf_rtps_type_object_base_type,
      { "Base Type Id", "rtps.type_object.base_type_id",
        FT_UINT64, BASE_HEX, 0x0, 0,
        NULL, HFILL }
    },
    { &hf_rtps_type_object_element_raw, {
        "Type Element Content", "rtps.type_object.element",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }
    },
    { &hf_rtps_type_object_type_property_name,
      { "Name", "rtps.type_object.property.name",
        FT_STRING, BASE_NONE, 0x0, 0,
        NULL, HFILL }
    },
    { &hf_rtps_type_object_member_id,
      { "Member Id", "rtps.type_object.annotation.member_id",
        FT_UINT32, BASE_DEC, 0x0, 0,
        NULL, HFILL }
    },
    { &hf_rtps_type_object_name,
      { "Name", "rtps.type_object.member.name",
        FT_STRING, BASE_NONE, 0x0, 0,
        NULL, HFILL }
    },
    { &hf_rtps_type_object_annotation_value_d,
      { "Annotation Member (_d)", "rtps.type_object.annotation.value_d",
        FT_UINT16, BASE_DEC, 0x0, 0,
        NULL, HFILL }
    },
    { &hf_rtps_type_object_annotation_value_16,
      { "16 bits type", "rtps.type_object.annotation.value",
        FT_UINT16, BASE_DEC, 0x0, 0,
        NULL, HFILL }
    },
    { &hf_rtps_type_object_union_label,
    { "Label", "rtps.type_object.union.label",
          FT_UINT32, BASE_DEC, 0x0, 0,
          NULL, HFILL }
    },
    { &hf_rtps_type_object_bound,
    { "Bound", "rtps.type_object.bound",
          FT_UINT32, BASE_DEC, 0x0, 0,
          NULL, HFILL }
    },
    { &hf_rtps_type_object_enum_constant_name,
      { "Enum name", "rtps.type_object.enum.name",
          FT_STRING, BASE_NONE, 0x0, 0,
          NULL, HFILL }
    },
    { &hf_rtps_type_object_enum_constant_value,
      { "Enum value", "rtps.type_object.enum.value",
          FT_INT32, BASE_DEC, 0x0, 0,
          NULL, HFILL }
    },
    { &hf_rtps_type_object_element_shared,
      { "Element shared", "rtps.type_object.shared",
          FT_BOOLEAN, 8, TFS(&tfs_true_false), 0,
          NULL, HFILL }
    },
    { &hf_rtps_flag_typeflag_final, {
        "FINAL", "rtps.flag.typeflags.final",
        FT_BOOLEAN, 16, TFS(&tfs_set_notset), 0x0001, NULL, HFILL }
    },
    { &hf_rtps_flag_typeflag_mutable, {
        "MUTABLE", "rtps.flag.typeflags.mutable",
        FT_BOOLEAN, 16, TFS(&tfs_set_notset), 0x0002, NULL, HFILL }
    },
    { &hf_rtps_flag_typeflag_nested, {
        "NESTED", "rtps.flag.typeflags.nested",
        FT_BOOLEAN, 16, TFS(&tfs_set_notset), 0x0004, NULL, HFILL }
    },
    { &hf_rtps_type_object_flags, {
        "Flags", "rtps.flag.typeflags",
        FT_UINT16, BASE_HEX, NULL, 0, NULL, HFILL }
    },
    { &hf_rtps_flag_memberflag_key, {
        "Key", "rtps.flag.typeflags.key",
        FT_BOOLEAN, 16, TFS(&tfs_set_notset), 0x0001, NULL, HFILL }
    },
    { &hf_rtps_flag_memberflag_optional, {
        "Optional", "rtps.flag.typeflags.optional",
        FT_BOOLEAN, 16, TFS(&tfs_set_notset), 0x0002, NULL, HFILL }
    },
    { &hf_rtps_flag_memberflag_shareable, {
        "Shareable", "rtps.flag.typeflags.shareable",
        FT_BOOLEAN, 16, TFS(&tfs_set_notset), 0x0004, NULL, HFILL }
    },
    { &hf_rtps_flag_memberflag_union_default, {
        "Union default", "rtps.flag.typeflags.union_default",
        FT_BOOLEAN, 16, TFS(&tfs_set_notset), 0x0008, NULL, HFILL }
    },
    { &hf_rtps_type_object_element_module_name,
      { "Module name", "rtps.type_object.module_name",
        FT_STRINGZ, BASE_NONE, NULL, 0,  NULL, HFILL }
    },
    { &hf_rtps_flag_service_request_writer, {
        "Service Request Writer", "rtps.flag.service_request_writer",
        FT_BOOLEAN, 32, TFS(&tfs_set_notset), 0x00000001, NULL, HFILL }
    },
    { &hf_rtps_flag_service_request_reader, {
        "Service Request Reader", "rtps.flag.service_request_reader",
        FT_BOOLEAN, 32, TFS(&tfs_set_notset), 0x00000002, NULL, HFILL }
    },
    { &hf_rtps_flag_locator_ping_writer, {
        "Locator Ping Writer", "rtps.flag.locator_ping_writer",
        FT_BOOLEAN, 32, TFS(&tfs_set_notset), 0x00000004, NULL, HFILL }
    },
    { &hf_rtps_flag_locator_ping_reader, {
        "Locator Ping Reader", "rtps.flag.locator_ping_reader",
        FT_BOOLEAN, 32, TFS(&tfs_set_notset), 0x00000008, NULL, HFILL }
    },
    { &hf_rtps_flag_secure_service_request_writer, {
        "Secure Service Request Writer", "rtps.flag.secure_service_request_writer",
        FT_BOOLEAN, 32, TFS(&tfs_set_notset), 0x00000010, NULL, HFILL }
    },
    { &hf_rtps_flag_secure_service_request_reader, {
        "Secure Service Request Reader", "rtps.flag.secure_service_request_reader",
        FT_BOOLEAN, 32, TFS(&tfs_set_notset), 0x00000020, NULL, HFILL }
    },
    { &hf_rtps_flag_security_access_protected, {
        "Access Protected", "rtps.flag.security.access_protected",
        FT_BOOLEAN, 32, TFS(&tfs_set_notset), 0x00000001, NULL, HFILL }
    },
    { &hf_rtps_flag_security_discovery_protected, {
        "Discovery Protected", "rtps.flag.security.discovery_protected",
        FT_BOOLEAN, 32, TFS(&tfs_set_notset), 0x00000002, NULL, HFILL }
    },
    { &hf_rtps_flag_security_submessage_protected, {
        "Submessage Protected", "rtps.flag.security.submessage_protected",
        FT_BOOLEAN, 32, TFS(&tfs_set_notset), 0x00000004, NULL, HFILL }
    },
    { &hf_rtps_flag_security_payload_protected, {
        "Payload Protected", "rtps.flag.security.payload_protected",
        FT_BOOLEAN, 32, TFS(&tfs_set_notset), 0x00000008, NULL, HFILL }
    },
    { &hf_rtps_flag_endpoint_security_attribute_flag_is_read_protected,{
        "Read Protected", "rtps.flag.security.info.read_protected",
        FT_BOOLEAN, 32, TFS(&tfs_set_notset), 0x00000001, NULL, HFILL }
    },
    { &hf_rtps_flag_endpoint_security_attribute_flag_is_write_protected,{
        "Write Protected", "rtps.flag.security.info.write_protected",
        FT_BOOLEAN, 32, TFS(&tfs_set_notset), 0x00000002, NULL, HFILL }
    },
    { &hf_rtps_flag_endpoint_security_attribute_flag_is_discovery_protected,{
        "Discovery Protected", "rtps.flag.security.info.discovery_protected",
        FT_BOOLEAN, 32, TFS(&tfs_set_notset), 0x00000004, NULL, HFILL }
    },
    { &hf_rtps_flag_endpoint_security_attribute_flag_is_submessage_protected,{
        "Submessage Protected", "rtps.flag.security.info.submessage_protected",
        FT_BOOLEAN, 32, TFS(&tfs_set_notset), 0x00000008, NULL, HFILL }
    },
    { &hf_rtps_flag_endpoint_security_attribute_flag_is_payload_protected,{
        "Payload Protected", "rtps.flag.security.info.payload_protected",
        FT_BOOLEAN, 32, TFS(&tfs_set_notset), 0x00000010, NULL, HFILL }
    },
    { &hf_rtps_flag_endpoint_security_attribute_flag_is_key_protected,{
        "Key Protected", "rtps.flag.security.info.key_protected",
        FT_BOOLEAN, 32, TFS(&tfs_set_notset), 0x00000020, NULL, HFILL }
    },
    { &hf_rtps_flag_endpoint_security_attribute_flag_is_liveliness_protected,{
        "Liveliness Protected", "rtps.flag.security.info.liveliness_protected",
        FT_BOOLEAN, 32, TFS(&tfs_set_notset), 0x00000040, NULL, HFILL }
    },
    { &hf_rtps_flag_endpoint_security_attribute_flag_is_valid,{
        "Mask Valid", "rtps.flag.security.info.valid",
        FT_BOOLEAN, 32, TFS(&tfs_set_notset), 0x80000000, NULL, HFILL }
    },
    { &hf_rtps_param_endpoint_security_attributes_mask,{
        "EndpointSecurityAttributesMask", "rtps.param.endpoint_security_attributes",
        FT_UINT32, BASE_HEX, NULL, 0,
        "Bitmask representing the EndpointSecurityAttributes flags in PID_ENDPOINT_SECURITY_INFO",
        HFILL }
    },
    { &hf_rtps_param_participant_security_symmetric_cipher_algorithms_builtin_endpoints_used_bit, {
        "Builtin Endpoints Used Bit", "rtps.param.participant_security_symmetric_cipher_algorithms.builtin_endpoints_used_bit",
        FT_UINT32, BASE_HEX, VALS(security_symmetric_cipher_bit_vals), 0,
        "Enum representing the Symmetric Cipher algorithm the builtin endpoints use",
        HFILL }
    },
    { &hf_rtps_param_endpoint_security_symmetric_cipher_algorithms_used_bit, {
        "Used Bit", "rtps.param.endpoint_security_symmetric_cipher_algorithm.used_bit",
        FT_UINT32, BASE_HEX, VALS(security_symmetric_cipher_bit_vals), 0,
        "Enum representing the Symmetric Cipher algorithm the endpoint uses",
        HFILL }
    },
    { &hf_rtps_param_participant_security_symmetric_cipher_algorithms_builtin_endpoints_key_exchange_used_bit, {
        "Key Exchange Builtin Endpoints Used Bit", "rtps.param.participant_security_symmetric_cipher_algorithms.builtin_endpoints_key_exchange_used_bit",
        FT_UINT32, BASE_HEX, VALS(security_symmetric_cipher_bit_vals), 0,
        "Enum representing the Symmetric Cipher algorithm the key exchange builtin endpoints use",
        HFILL }
    },
    { &hf_rtps_param_participant_security_symmetric_cipher_algorithms_supported_mask, {
        "Supported Mask", "rtps.param.participant_security_symmetric_cipher_algorithms.supported_mask",
        FT_UINT32, BASE_HEX, 0, 0, "Bitmask representing Symmetric Cipher algorithms the participant supports",
		HFILL }
    },
    { &hf_rtps_flag_security_symmetric_cipher_mask_aes128_gcm, {
        "AES128 GCM", "rtps.flag.security_symmetric_cipher_mask.aes128_gcm",
        FT_BOOLEAN, 32, TFS(&tfs_set_notset), SECURITY_SYMMETRIC_CIPHER_BIT_AES128_GCM, NULL, HFILL }
    },
    { &hf_rtps_flag_security_symmetric_cipher_mask_aes256_gcm, {
        "AES256 GCM", "rtps.flag.security_symmetric_cipher_mask.aes256_gcm",
        FT_BOOLEAN, 32, TFS(&tfs_set_notset), SECURITY_SYMMETRIC_CIPHER_BIT_AES256_GCM, NULL, HFILL }
    },
    { &hf_rtps_flag_security_symmetric_cipher_mask_custom_algorithm, {
        "Custom Algorithm", "rtps.flag.security_symmetric_cipher_mask.custom_algorithm",
        FT_BOOLEAN, 32, TFS(&tfs_set_notset), SECURITY_SYMMETRIC_CIPHER_BIT_CUSTOM_ALGORITHM, NULL, HFILL }
    },
    { &hf_rtps_param_participant_security_key_establishment_algorithms_preferred_bit, {
        "Preferred Bit", "rtps.param.participant_security_key_establishment_algorithms.preferred_bit",
        FT_UINT32, BASE_HEX, VALS(security_key_establishment_bit_vals), 0,
        "Enum representing the Key Establishment algorithm the participant will use if it is the authentication initiator",  HFILL }
    },
    { &hf_rtps_param_participant_security_digital_signature_algorithms_auth_used_bit, {
        "Authentication Used Bit", "rtps.articipant_security_digital_signature_algorithms.auth_used_bit",
        FT_UINT32, BASE_HEX, VALS(security_digital_signature_bit_vals), 0,
        "Enum representing the Digital Signature algorithm the participant will use during Authentication",  HFILL }
    },
    { &hf_rtps_param_participant_security_key_establishment_algorithms_supported_mask, {
        "Supported Mask", "rtps.param.participant_security_key_establishment_algorithms.supported_mask",
        FT_UINT32, BASE_HEX, 0, 0, "Bitmask representing the Key Establishment algorithms the participant supports",
		HFILL }
    },
    { &hf_rtps_flag_security_key_establishment_mask_dhe_modp2048256, {
        "DHE_MODP2048256", "rtps.flag.security_key_establishment_mask.dhe_modp2048256",
        FT_BOOLEAN, 32, TFS(&tfs_set_notset), SECURITY_KEY_ESTABLISHMENT_BIT_DHE_MODP2048256, NULL, HFILL }
    },
    { &hf_rtps_flag_security_key_establishment_mask_ecdheceum_p256, {
        "ECDHECEUM_P256", "rtps.flag.security_key_establishment_mask.ecdheceum_p256",
        FT_BOOLEAN, 32, TFS(&tfs_set_notset), SECURITY_KEY_ESTABLISHMENT_BIT_ECDHECEUM_P256, NULL, HFILL }
    },
    { &hf_rtps_flag_security_key_establishment_mask_ecdheceum_p384, {
        "ECDHECEUM_P384", "rtps.flag.security_key_establishment_mask.ecdheceum_p384",
        FT_BOOLEAN, 32, TFS(&tfs_set_notset), SECURITY_KEY_ESTABLISHMENT_BIT_ECDHECEUM_P384, NULL, HFILL }
    },
    { &hf_rtps_flag_security_key_establishment_mask_custom_algorithm, {
        "Custom Algorithm", "rtps.flag.security_key_establishment_mask.custom_algorithm",
        FT_BOOLEAN, 32, TFS(&tfs_set_notset), SECURITY_KEY_ESTABLISHMENT_BIT_CUSTOM_ALGORITHM, NULL, HFILL }
    },
    { &hf_rtps_flag_plugin_endpoint_security_attribute_flag_is_payload_encrypted, {
        "Submessage Encrypted", "rtps.flag.security.info.plugin_submessage_encrypted",
        FT_BOOLEAN, 32, TFS(&tfs_set_notset), 0x00000001, NULL, HFILL }
    },
    { &hf_rtps_param_participant_security_digital_signature_algorithms_trust_chain_supported_mask, {
        "Trust Chain Supported Mask", "rtps.param.participant_security_digital_signature_algorithms.trust_chain_supported_mask",
        FT_UINT32, BASE_HEX, 0, 0, "Bitmask representing the Trust Chain Digital Signature algorithms the participant supports", HFILL }
    },
    { &hf_rtps_param_participant_security_digital_signature_algorithms_trust_chain_used_mask, {
        "Trust Chain Used Mask", "rtps.param.participant_security_digital_signature_algorithms.trust_chain_used_mask",
        FT_UINT32, BASE_HEX, 0, 0, "Bitmask representing the Digital Signature algorithms the participant will use to build its Trust Chain", HFILL }
    },
    { &hf_rtps_param_participant_security_digital_signature_algorithms_auth_supported_mask, {
        "Authentication Supported Mask", "rtps.param.participant_security_digital_signature_algorithms.auth_supported_mask",
        FT_UINT32, BASE_HEX, 0, 0, "Bitmask representing the Authentication Digital Signature algorithms the participant supports", HFILL }
    },
    { &hf_rtps_flag_security_digital_signature_mask_rsassapssmgf1sha256_2048_sha256, {
        "RSASSAPSSMGF1SHA256_2048_SHA256", "rtps.flag.security_digital_signature_mask.rsassapssmgf1sha256_2048_sha256",
        FT_BOOLEAN, 32, TFS(&tfs_set_notset), SECURITY_DIGITAL_SIGNATURE_BIT_RSASSAPSSMGF1SHA256_2048_SHA256, NULL, HFILL }
    },
    { &hf_rtps_flag_security_digital_signature_mask_rsassapkcs1v15_2048_sha256, {
        "RSASSAPKCS1V15_2048_SHA256", "rtps.flag.security_digital_signature_mask.rsassapkcs1v15_2048_sha256",
        FT_BOOLEAN, 32, TFS(&tfs_set_notset), SECURITY_DIGITAL_SIGNATURE_BIT_RSASSAPKCS1V15_2048_SHA256, NULL, HFILL }
    },
    { &hf_rtps_flag_security_digital_signature_mask_ecdsa_p256_sha256, {
        "ECDSA_P256_SHA256", "rtps.flag.security_digital_signature_mask.ecdsa_p256_sha256",
        FT_BOOLEAN, 32, TFS(&tfs_set_notset), SECURITY_DIGITAL_SIGNATURE_BIT_ECDSA_P256_SHA256, NULL, HFILL }
    },
    { &hf_rtps_flag_security_digital_signature_mask_ecdsa_p384_sha384, {
        "ECDSA_P384_SHA384", "rtps.flag.security_digital_signature_mask.ecdsa_p384_sha384",
        FT_BOOLEAN, 32, TFS(&tfs_set_notset), SECURITY_DIGITAL_SIGNATURE_BIT_ECDSA_P384_SHA384, NULL, HFILL }
    },
    { &hf_rtps_flag_security_digital_signature_mask_custom_algorithm, {
        "Custom Algorithm", "rtps.flag.security_digital_signature_mask.custom_algorithm",
        FT_BOOLEAN, 32, TFS(&tfs_set_notset), SECURITY_DIGITAL_SIGNATURE_BIT_CUSTOM_ALGORITHM, NULL, HFILL }
    },
    { &hf_rtps_flag_plugin_endpoint_security_attribute_flag_is_key_encrypted,{
        "Payload Encrypted", "rtps.flag.security.info.plugin_payload_encrypted",
        FT_BOOLEAN, 32, TFS(&tfs_set_notset), 0x00000002, NULL, HFILL }
    },
    { &hf_rtps_flag_plugin_endpoint_security_attribute_flag_is_liveliness_encrypted,{
        "Submessage Origin Encrypted", "rtps.flag.security.info.plugin_liveliness_encrypted",
        FT_BOOLEAN, 32, TFS(&tfs_set_notset), 0x00000004, NULL, HFILL }
    },
    { &hf_rtps_flag_plugin_endpoint_security_attribute_flag_is_valid,{
        "Mask Valid", "rtps.flag.security.info.plugin_valid",
        FT_BOOLEAN, 32, TFS(&tfs_set_notset), 0x80000000, NULL, HFILL }
    },
    { &hf_rtps_param_plugin_endpoint_security_attributes_mask,{
        "PluginEndpointSecurityAttributesMask (valid dissection if using the Specification Builtin Plugins)",
        "rtps.param.plugin_endpoint_security_attributes",
        FT_UINT32, BASE_HEX, NULL, 0,
        "bitmask representing the PluginEndpointSecurityAttributes flags in PID_ENDPOINT_SECURITY_INFO",
        HFILL }
    },
    { &hf_rtps_flag_participant_security_attribute_flag_is_rtps_protected,{
        "RTPS Protected", "rtps.flag.security.info.participant_rtps_protected",
        FT_BOOLEAN, 32, TFS(&tfs_set_notset), 0x00000001, NULL, HFILL }
    },
    { &hf_rtps_flag_participant_security_attribute_flag_is_discovery_protected,{
        "Discovery Protected", "rtps.flag.security.info.participant_discovery_protected",
        FT_BOOLEAN, 32, TFS(&tfs_set_notset), 0x00000002, NULL, HFILL }
    },
    { &hf_rtps_flag_participant_security_attribute_flag_is_liveliness_protected,{
        "Liveliness Protected", "rtps.flag.security.info.participant_liveliness_protected",
        FT_BOOLEAN, 32, TFS(&tfs_set_notset), 0x00000004, NULL, HFILL }
    },
    { &hf_rtps_flag_participant_security_attribute_flag_is_valid,{
        "Mask Valid", "rtps.flag.security.info.participant_mask_valid",
        FT_BOOLEAN, 32, TFS(&tfs_set_notset), 0x80000000, NULL, HFILL }
    },
    { &hf_rtps_param_participant_security_attributes_mask,{
        "ParticipantSecurityAttributesMask",
        "rtps.param.participant_security_attributes",
        FT_UINT32, BASE_HEX, NULL, 0,
        "bitmask representing the ParticipantSecurityAttributes flags in PID_PARTICIPANT_SECURITY_INFO",
        HFILL }
    },
    { &hf_rtps_flag_plugin_participant_security_attribute_flag_is_rtps_encrypted,{
        "RTPS Encrypted", "rtps.flag.security.info.plugin_participant_rtps_encrypted",
        FT_BOOLEAN, 32, TFS(&tfs_set_notset), 0x00000001, NULL, HFILL }
    },
    { &hf_rtps_flag_plugin_participant_security_attribute_flag_is_discovery_encrypted,{
        "Discovery Encrypted", "rtps.flag.security.info.plugin_participant_discovery_encrypted",
        FT_BOOLEAN, 32, TFS(&tfs_set_notset), 0x00000002, NULL, HFILL }
    },
    { &hf_rtps_flag_plugin_participant_security_attribute_flag_is_liveliness_encrypted,{
        "Liveliness Encrypted", "rtps.flag.security.info.plugin_participant_liveliness_encrypted",
        FT_BOOLEAN, 32, TFS(&tfs_set_notset), 0x00000004, NULL, HFILL }
    },
    { &hf_rtps_flag_plugin_participant_security_attribute_flag_is_rtps_origin_encrypted,{
        "RTPS Origin Encrypted", "rtps.flag.security.info.plugin_participant_rtps_origin_encrypted",
        FT_BOOLEAN, 32, TFS(&tfs_set_notset), 0x00000008, NULL, HFILL }
    },
    { &hf_rtps_flag_plugin_participant_security_attribute_flag_is_discovery_origin_encrypted,{
        "Discovery Origin Encrypted", "rtps.flag.security.info.plugin_participant_discovery_origin_encrypted",
        FT_BOOLEAN, 32, TFS(&tfs_set_notset), 0x00000010, NULL, HFILL }
    },
    { &hf_rtps_flag_plugin_participant_security_attribute_flag_is_liveliness_origin_encrypted,{
        "Liveliness Origin Encrypted", "rtps.flag.security.info.plugin_participant_liveliness_origin_encrypted",
        FT_BOOLEAN, 32, TFS(&tfs_set_notset), 0x00000020, NULL, HFILL }
    },
    { &hf_rtps_flag_plugin_participant_security_attribute_flag_is_valid,{
        "Mask Valid", "rtps.flag.security.info.plugin_participant_mask_valid",
        FT_BOOLEAN, 32, TFS(&tfs_set_notset), 0x80000000, NULL, HFILL }
    },
    { &hf_rtps_param_plugin_participant_security_attributes_mask,{
        "PluginParticipantSecurityAttributesMask (valid dissection if using the Specification Builtin Plugins)",
        "rtps.param.plugin_participant_security_attributes",
        FT_UINT32, BASE_HEX, NULL, 0,
        "bitmask representing the PluginParticipantSecurityAttributes flags in PID_PARTICIPANT_SECURITY_INFO",
        HFILL }
    },
    { &hf_rtps_param_enable_authentication,
      { "Authentication enabled", "rtps.secure.enable_authentication",
        FT_BOOLEAN, 32, TFS(&tfs_true_false), 0, NULL, HFILL }
    },
    { &hf_rtps_param_builtin_endpoint_qos,
      { "Built-in Endpoint QoS", "rtps.param.builtin_endpoint_qos",
        FT_UINT32, BASE_HEX, NULL, 0, NULL, HFILL }
    },
    { &hf_rtps_param_sample_signature_epoch,
      { "Epoch", "rtps.sample_signature.epoch",
        FT_UINT64, BASE_DEC, NULL, 0, NULL, HFILL }
    },
    { &hf_rtps_param_sample_signature_nonce,
      { "Nonce", "rtps.sample_signature.nonce",
        FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }
    },
    { &hf_rtps_param_sample_signature_length,
      {"Signature Length", "rtps.sample_signature.signature_length",
        FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }
    },
    { &hf_rtps_param_sample_signature_signature,
      { "Signature", "rtps.sample_signature.signature",
        FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL }
    },
    { &hf_rtps_secure_dataheader_transformation_kind, {
        "Transformation Kind", "rtps.secure.data_header.transformation_kind",
        FT_INT32, BASE_DEC, VALS(secure_transformation_kind), 0,
        NULL, HFILL }
    },
    { &hf_rtps_secure_dataheader_transformation_key_id, {
        "Transformation Key Id", "rtps.secure.data_header.transformation_key",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }
    },
    { &hf_rtps_secure_dataheader_plugin_sec_header, {
        "Plugin Secure Header", "rtps.secure.data_header.plugin_sec_header",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }
    },
    { &hf_rtps_secure_datatag_plugin_sec_tag, {
        "Plugin Secure Tag", "rtps.secure.data_tag.plugin_sec_tag",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }
    },
    { &hf_rtps_srm_service_id,
      { "Service Id", "rtps.srm.service_id",
        FT_INT32, BASE_DEC, VALS(service_request_kind), 0, NULL, HFILL }
    },
    { &hf_rtps_srm_request_body, {
        "Request Body", "rtps.srm.request_body",
        FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL }
    },
    { &hf_rtps_srm_instance_id, {
        "Instance Id", "rtps.srm.instance_id",
         FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL }
    },
    { &hf_rtps_topic_query_selection_filter_class_name,
      { "Class Name", "rtps.srm.topic_query.class_name",
        FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }
    },
    { &hf_rtps_topic_query_selection_filter_expression,
      { "Filter Expression", "rtps.srm.topic_query.filter_expression",
        FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }
    },
    { &hf_rtps_topic_query_selection_filter_parameter,
      { "Filter Parameter", "rtps.srm.topic_query.filter_parameter",
        FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }
    },
    { &hf_rtps_topic_query_selection_num_parameters,
      { "Number of Filter Parameters", "rtps.srm.topic_query.num_filter_parameters",
        FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }
    },
    { &hf_rtps_topic_query_topic_name,
      { "Topic Name", "rtps.srm.topic_query.topic_name",
        FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }
    },
    { &hf_rtps_topic_query_original_related_reader_guid,
      { "Original Related Reader GUID", "rtps.srm.topic_query.original_related_reader_guid",
        FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL }
    },
    { &hf_rtps_secure_secure_data_length,
      { "Secure Data Length", "rtps.secure.secure_data_length",
        FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }
    },
    { &hf_rtps_secure_secure_data,
      { "Secure Data", "rtps.secure.secure_data",
        FT_BYTES, BASE_NONE, NULL, 0, "The user data transferred in a secure payload", HFILL }
    },
    { &hf_rtps_pgm, {
       "Participant Generic Message", "rtps.pgm",
       FT_BOOLEAN, 8, TFS(&tfs_set_notset), 0x0, NULL, HFILL }
    },
    { &hf_rtps_srm, {
       "Service Request Message", "rtps.srm",
       FT_BOOLEAN, 8, TFS(&tfs_set_notset), 0x0, NULL, HFILL }
    },
    { &hf_rtps_pgm_dst_participant_guid,
      { "Destination Participant GUID", "rtps.pgm.dst_participant_guid",
        FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL }
    },
    { &hf_rtps_source_participant_guid,
      { "Source Participant GUID", "rtps.pgm.source_participant_guid",
        FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL }
    },
    { &hf_rtps_pgm_dst_endpoint_guid,
      { "Destination Endpoint GUID", "rtps.pgm.dst_endpoint_guid",
        FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL }
    },
    { &hf_rtps_pgm_src_endpoint_guid,
      { "Source Endpoint GUID", "rtps.pgm.src_endpoint_guid",
        FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL }
    },
    { &hf_rtps_message_identity_source_guid,
      { "Source GUID", "rtps.pgm.message_identity.source_guid",
        FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL }
    },
    { &hf_rtps_pgm_message_class_id,
      { "Message class id", "rtps.pgm.data_holder.message_class_id",
        FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }
    },
    { &hf_rtps_pgm_data_holder_class_id,
      { "Class Id", "rtps.pgm.data_holder.class_id",
        FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }
    },
#if 0
    { &hf_rtps_pgm_data_holder_stringseq_size,
      { "Size", "rtps.pgm.data_holder.string_seq_size",
        FT_INT32, BASE_DEC, NULL, 0, NULL, HFILL }
    },
    { &hf_rtps_pgm_data_holder_stringseq_name,
      { "Name", "rtps.pgm.data_holder.string_seq_name",
        FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }
    },
    { &hf_rtps_pgm_data_holder_long_long,
      { "Long long", "rtps.pgm.data_holder.long_long",
        FT_INT64, BASE_DEC, NULL, 0, NULL, HFILL }
    },
#endif
    { &hf_rtps_param_topic_query_publication_enable,
      { "Enable", "rtps.param.topic_query_publication_enable",
        FT_BOOLEAN, 8, TFS(&tfs_true_false), 0, NULL, HFILL }
    },
    { &hf_rtps_param_topic_query_publication_sessions,
      { "Number of sessions", "rtps.param.topic_query_publication_sessions",
        FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }
    },
    { &hf_rtps_pl_cdr_member,
      { "Member value", "rtps.data.value",
        FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL }
    },
    { &hf_rtps_pl_cdr_member_id,
      { "Member ID", "rtps.data.member_id",
        FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL }
    },
    { &hf_rtps_pl_cdr_member_length,
      { "Member length", "rtps.data.member_length",
        FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL }
    },
    { &hf_rtps_pl_cdr_member_id_ext,
      { "Member ID", "rtps.data.member_id",
        FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }
    },
    { &hf_rtps_pl_cdr_member_length_ext,
      { "Member length", "rtps.data.member_length",
        FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }
    },
    { &hf_rtps_dcps_publication_data_frame_number,{
        "DCPSPublicationData In", "rtps.dcps_publication_data_frame_number",
        FT_FRAMENUM, BASE_NONE, NULL, 0x0,
        "This is a submessage sent by the DataWriter described in the DCPSPublicationData found in this frame", HFILL }
    },
    { &hf_rtps_data_tag_name,
        { "Name", "rtps.param.data_tag.name",
        FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }
    },
    { &hf_rtps_data_tag_value,
        { "Value", "rtps.param.data_tag.value",
        FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }
    },
    { &hf_rtps_fragments,
        { "Message fragments", "rtps.fragments",
        FT_NONE, BASE_NONE, NULL, 0x00, NULL, HFILL }
    },
    { &hf_rtps_fragment,
        { "Message fragment", "rtps.fragment",
        FT_FRAMENUM, BASE_NONE, NULL, 0x00, NULL, HFILL }
    },
    { &hf_rtps_fragment_overlap,
        { "Message fragment overlap", "rtps.fragment.overlap",
        FT_BOOLEAN, 0, NULL, 0x00, NULL, HFILL }
    },
    { &hf_rtps_fragment_overlap_conflict,
        { "Message fragment overlapping with conflicting data", "rtps.fragment.overlap.conflicts",
        FT_BOOLEAN, 0, NULL, 0x00, NULL, HFILL }
    },
    { &hf_rtps_fragment_multiple_tails,
        { "Message has multiple tail fragments", "rtps.fragment.multiple_tails",
        FT_BOOLEAN, 0, NULL, 0x00, NULL, HFILL }
    },
    { &hf_rtps_fragment_too_long_fragment,
        { "Message fragment too long", "rtps.fragment.too_long_fragment",
        FT_BOOLEAN, 0, NULL, 0x00, NULL, HFILL }
    },
    { &hf_rtps_fragment_error,
        { "Message defragmentation error", "rtps.fragment.error",
        FT_FRAMENUM, BASE_NONE, NULL, 0x00, NULL, HFILL }
    },
    { &hf_rtps_fragment_count,
        { "Message fragment count", "rtps.fragment.count",
        FT_UINT32, BASE_DEC, NULL, 0x00, NULL, HFILL }
    },
    { &hf_rtps_reassembled_in,
        { "Reassembled in", "rtps.reassembled.in",
        FT_FRAMENUM, BASE_NONE, NULL, 0x00, NULL, HFILL }
    },
    { &hf_rtps_reassembled_length,
        { "Reassembled length", "rtps.reassembled.length",
        FT_UINT32, BASE_DEC, NULL, 0x00, NULL, HFILL }
    },
    { &hf_rtps_reassembled_data,
        { "Reassembled RTPS data", "rtps.reassembled.data", FT_BYTES, BASE_NONE,
        NULL, 0x0, "The reassembled payload", HFILL }
    },
    { &hf_rtps_compression_plugin_class_id,
        { "Compression class Id", "rtps.param.compression_class_id", FT_UINT32, BASE_DEC,
        VALS(class_id_enum_names), 0x0, NULL, HFILL }
    },
    { &hf_rtps_encapsulation_options_compression_plugin_class_id,
        { "Compression class Id", "rtps.param.compression_class_id", FT_INT8, BASE_DEC,
        VALS(class_id_enum_names), 0x0, NULL, HFILL }
    },
    { &hf_rtps_padding_bytes,
        { "Padding bytes", "rtps.padding_bytes", FT_INT8, BASE_DEC,
        NULL, 0x0, NULL, HFILL }
    },
    { &hf_rtps_uncompressed_serialized_length,
        { "Uncompressed serialized length", "rtps.param.uncompressed_serialized_length", FT_UINT32, BASE_DEC,
        NULL, 0x0, "The reassembled payload", HFILL }
    },

    { &hf_rtps_encapsulation_extended_compression_options,
        { "Uncompressed serialized length", "rtps.extended_compression_options", FT_UINT32, BASE_DEC,
        NULL, 0x0, "Extended compression options", HFILL }
    },
    { &hf_rtps_compressed_serialized_type_object,
        { "Compressed serialized type object", "rtps.param.compressed_serialized_typeobject", FT_BYTES, BASE_NONE,
        NULL, 0x0, "The reassembled payload", HFILL }
    },

    { &hf_rtps_dissection_boolean,
      {"BOOLEAN", "rtps.dissection.boolean",
        FT_BOOLEAN, BASE_DEC, NULL, 0, NULL, HFILL }
    },

    { &hf_rtps_dissection_byte,
      {"BYTE", "rtps.dissection.byte",
        FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }
    },

    { &hf_rtps_dissection_int16,
      {"INT16", "rtps.dissection.int16",
        FT_INT16, BASE_DEC, NULL, 0, NULL, HFILL }
    },

    { &hf_rtps_dissection_uint16,
      {"UINT16", "rtps.dissection.uint16",
        FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL }
    },

    { &hf_rtps_dissection_int32,
      {"INT32", "rtps.dissection.int32",
        FT_INT32, BASE_DEC, NULL, 0, NULL, HFILL }
    },

    { &hf_rtps_dissection_uint32,
      {"UINT32", "rtps.dissection.uint32",
        FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }
    },

    { &hf_rtps_dissection_int64,
      {"INT64", "rtps.dissection.int64",
        FT_INT64, BASE_DEC, NULL, 0, NULL, HFILL }
    },

    { &hf_rtps_dissection_uint64,
      {"UINT64", "rtps.dissection.uint64",
        FT_UINT64, BASE_DEC, NULL, 0, NULL, HFILL }
    },

    { &hf_rtps_dissection_float,
      {"FLOAT", "rtps.dissection.float",
        FT_FLOAT, BASE_NONE, NULL, 0, NULL, HFILL }
    },

    { &hf_rtps_dissection_double,
      {"DOUBLE", "rtps.dissection.double",
        FT_DOUBLE, BASE_NONE, NULL, 0, NULL, HFILL }
    },

    { &hf_rtps_dissection_int128,
      {"INT128", "rtps.dissection.int128",
        FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL }
    },

    { &hf_rtps_dissection_string,
      { "STRING", "rtps.dissection.string",
        FT_STRINGZ, BASE_NONE, NULL, 0, NULL, HFILL }
    },
    { &hf_rtps_flag_udpv4_wan_locator_u, {
        "UUID Locator", "rtps.flag.udpv4_wan_locator.u",
        FT_BOOLEAN, 8, TFS(&tfs_set_notset), 0x01, NULL, HFILL }
    },
    { &hf_rtps_flag_udpv4_wan_locator_p, {
        "Public Locator", "rtps.flag.udpv4_wan_locator.p",
        FT_BOOLEAN, 8, TFS(&tfs_set_notset), 0x02, NULL, HFILL }
    },
    { &hf_rtps_flag_udpv4_wan_locator_b, {
        "Bidirectional Locator", "rtps.flag.udpv4_wan_locator.b",
        FT_BOOLEAN, 8, TFS(&tfs_set_notset), 0x04, NULL, HFILL }
    },
    { &hf_rtps_flag_udpv4_wan_locator_r, {
        "Relay Locator", "rtps.flag.udpv4_wan_locator.r",
        FT_BOOLEAN, 8, TFS(&tfs_set_notset), 0x08, NULL, HFILL }
    },
    { &hf_rtps_udpv4_wan_locator_flags, {
        "Flags", "rtps.flag.udpv4_wan_locator",
        FT_UINT8, BASE_HEX, NULL, 0, "Bitmask representing the flags UDPv4 WAN locator", HFILL }
    },
    { &hf_rtps_uuid,{
        "UUID", "rtps.uuid",
        FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL }
    },
    { &hf_rtps_udpv4_wan_locator_public_ip, {
        "Public IP", "rtps.udpv4_wan_locator.public_ip",
        FT_IPv4, BASE_NONE, NULL, 0, NULL, HFILL }
    },
    { &hf_rtps_udpv4_wan_locator_public_port, {
        "Public port", "rtps.udpv4_wan_locator.public_port",
        FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL }
    },
    { &hf_rtps_udpv4_wan_locator_local_ip,{
        "Local IP", "rtps.udpv4_wan_locator.local_ip",
        FT_IPv4, BASE_NONE, NULL, 0, NULL, HFILL }
    },
    { &hf_rtps_udpv4_wan_locator_local_port,{
        "Local port", "rtps.udpv4_wan_locator.local_port",
        FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL }
    },
    { &hf_rtps_flag_udpv4_wan_binding_ping_e, {
        "Endianness", "rtps.flag.udpv4_wan_binding_ping.e",
        FT_BOOLEAN, 8, TFS(&tfs_set_notset), 0x01, NULL, HFILL }
    },
    { &hf_rtps_flag_udpv4_wan_binding_ping_l, {
        "Long address", "rtps.flag.udpv4_wan_binding_ping.l",
        FT_BOOLEAN, 8, TFS(&tfs_set_notset), 0x02, NULL, HFILL }
    },
    { &hf_rtps_flag_udpv4_wan_binding_ping_b,{
        "Bidirectional", "rtps.flag.udpv4_wan_binding_ping.b",
        FT_BOOLEAN, 8, TFS(&tfs_set_notset), 0x04, NULL, HFILL }
    },
    { &hf_rtps_udpv4_wan_binding_ping_flags, {
        "Flags", "rtps.flag.udpv4_wan_binding_ping",
        FT_UINT8, BASE_HEX, NULL, 0, "Bitmask representing the flags UDPv4 WAN binding ping", HFILL }
    },
    { &hf_rtps_udpv4_wan_binding_ping_port, {
        "RTPS port", "rtps.flag.udpv4_wan_binding_rtps_port",
        FT_UINT32, BASE_DEC, NULL, 0, "UDPv4 WAN binding ping RTPS port", HFILL }
    },
    { &hf_rtps_long_address, {
        "Long address", "rtps.long_address", FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL }
    },
    { &hf_rtps_param_group_coherent_set, {
        "Group coherent set sequence number", "rtps.param.group_coherent_set",
        FT_UINT64, BASE_DEC, NULL, 0, "Decimal value representing the value of PID_GROUP_COHERENT_SET parameter", HFILL }
    },
    { &hf_rtps_param_end_group_coherent_set, {
        "End group coherent set sequence number", "rtps.param.end_group_coherent_set",
        FT_UINT64, BASE_DEC, NULL, 0, "Decimal value representing the value of PID_END_GROUP_COHERENT_SET parameter", HFILL }
    },
    { &hf_rtps_param_mig_end_coherent_set_sample_count, {
        "Ended coherent set sample count", "rtps.param.mig_end_coherent_set_sample_count",
        FT_UINT32, BASE_DEC, NULL, 0, "Decimal value representing the value of MIG_RTPS_PID_END_COHERENT_SET_SAMPLE_COUNT parameter", HFILL }
    },
    { &hf_rtps_flag_cloud_discovery_service_announcer,{
        "Cloud Discovery Service Announcer", "rtps.flag.cloud_discovery_service_announcer",
        FT_BOOLEAN, 32, TFS(&tfs_set_notset), 0x00000040, NULL, HFILL }
    }
  };

  static gint *ett[] = {
    &ett_rtps,
    &ett_rtps_default_mapping,
    &ett_rtps_proto_version,
    &ett_rtps_product_version,
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
    &ett_rtps_timestamp,
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
    &ett_rtps_sample_batch_list,
    &ett_rtps_locator_filter_locator,
    &ett_rtps_writer_heartbeat_virtual_list,
    &ett_rtps_writer_heartbeat_virtual,
    &ett_rtps_virtual_guid_heartbeat_virtual_list,
    &ett_rtps_virtual_guid_heartbeat_virtual,
    &ett_rtps_app_ack_virtual_writer_list,
    &ett_rtps_app_ack_virtual_writer,
    &ett_rtps_app_ack_virtual_writer_interval_list,
    &ett_rtps_app_ack_virtual_writer_interval,
    &ett_rtps_transport_info,
    &ett_rtps_property_list,
    &ett_rtps_property,
    &ett_rtps_topic_info,
    &ett_rtps_topic_info_dw_qos,
    &ett_rtps_type_object,
    &ett_rtps_type_library,
    &ett_rtps_type_element,
    &ett_rtps_type_annotation_usage_list,
    &ett_rtps_type_enum_constant,
    &ett_rtps_type_bound_list,
    &ett_rtps_secure_payload_tree,
    &ett_rtps_secure_dataheader_tree,
    &ett_rtps_pgm_data,
    &ett_rtps_message_identity,
    &ett_rtps_related_message_identity,
    &ett_rtps_data_holder_seq,
    &ett_rtps_data_holder,
    &ett_rtps_data_holder_properties,
    &ett_rtps_property_tree,
    &ett_rtps_param_header_tree,
    &ett_rtps_custom_dissection_info,
    &ett_rtps_service_request_tree,
    &ett_rtps_locator_ping_tree,
    &ett_rtps_locator_reachability_tree,
    &ett_rtps_locator_list_tree,
    &ett_rtps_topic_query_tree,
    &ett_rtps_topic_query_selection_tree,
    &ett_rtps_topic_query_filter_params_tree,
    &ett_rtps_data_member,
    &ett_rtps_data_tag_seq,
    &ett_rtps_data_tag_item,
    &ett_rtps_fragment,
    &ett_rtps_fragments,
    &ett_rtps_data_representation,
    &ett_rtps_decompressed_type_object,
    &ett_rtps_dissection_tree,
    &ett_rtps_info_remaining_items,
    &ett_rtps_data_encapsulation_options,
    &ett_rtps_decompressed_serialized_data
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
     { &pid_type_csonsistency_invalid_size, { "rtps.pid_type_consistency_invalid_size", PI_MALFORMED, PI_ERROR, "PID_TYPE_CONSISTENCY invalid size. Has a size of %d bytes. Expected %d or %d bytes.", EXPFILL }},
     { &ei_rtps_uncompression_error, { "rtps.uncompression_error", PI_PROTOCOL, PI_WARN, "Unable to uncompress the compressed payload.", EXPFILL }}
  };

  module_t *rtps_module;
  expert_module_t *expert_rtps;

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

  prefs_register_bool_preference(rtps_module, "enable_max_dissection_info_elements",
            "Limit the number of elements dissected in structs",
            "Enabling this option may affect "
            "performance if the trace has messages with large Data Types.",
            &enable_max_data_type_elements);

  prefs_register_uint_preference(rtps_module, "max_dissection_info_elements",
            "Max Dissection info elements shown in structs",
            "Specifies the maximum number of Data Type elements dissected. "
            "Increasing this value may affect "
            "performance if the trace has messages with large Data Types.",
            10, &rtps_max_data_type_elements);

  prefs_register_bool_preference(rtps_module, "enable_max_dissection_array_elements",
            "Limit the number of elements dissected in arrays or sequences",
            "Disabling this option may affect "
            "performance if the trace has messages with large arrays or sequences.",
            &enable_max_array_data_type_elements);

  prefs_register_uint_preference(rtps_module, "max_dissection_array_elements",
            "Max Dissection elements shown in arrays or sequences",
            "Specifies the maximum number of Data Type elements dissected in arrays or sequences. "
            "Increasing this value may affect "
            "performance if the trace has messages with large Data Types.",
            10, &rtps_max_array_data_type_elements);

  prefs_register_bool_preference(rtps_module, "enable_topic_info",
              "Enable Topic Information",
              "Shows the Topic Name and Type Name of the samples. "
              "Note: this can considerably increase the dissection time",
              &enable_topic_info);

  prefs_register_bool_preference(rtps_module, "enable_user_data_dissection",
              "Enable User Data Dissection (based on Type Object)",
              "Dissects the user data if the Type Object is propagated in Discovery.",
              &enable_user_data_dissection);

  prefs_register_bool_preference(rtps_module, "enable_rtps_reassembly",
      "Enable RTPS Reassembly",
      "Enables the reassembly of DATA_FRAG submessages.",
      &enable_rtps_reassembly);

  rtps_type_name_table = register_dissector_table("rtps.type_name", "RTPS Type Name",
          proto_rtps, FT_STRING, BASE_NONE);

  registry = wmem_map_new_autoreset(wmem_epan_scope(), wmem_file_scope(), hash_by_guid, compare_by_guid);
  dissection_infos = wmem_map_new_autoreset(wmem_epan_scope(), wmem_file_scope(), g_int64_hash, g_int64_equal);
  union_member_mappings = wmem_map_new_autoreset(wmem_epan_scope(), wmem_file_scope(), g_int64_hash, g_int64_equal);
  mutable_member_mappings = wmem_map_new_autoreset(wmem_epan_scope(), wmem_file_scope(), g_int64_hash, g_int64_equal);
  coherent_set_tracking.entities_using_map = wmem_map_new_autoreset(wmem_epan_scope(), wmem_file_scope(), hash_by_guid, compare_by_guid);
  coherent_set_tracking.coherent_set_registry_map = wmem_map_new_autoreset(wmem_epan_scope(), wmem_file_scope(), coherent_set_key_hash_by_key, compare_by_coherent_set_key);

  coherent_set_tracking.entities_using_map = wmem_map_new_autoreset(wmem_epan_scope(), wmem_file_scope(), hash_by_guid, compare_by_guid);
  discovered_tcp_participants = wmem_map_new_autoreset(wmem_epan_scope(), wmem_file_scope(), hash_by_guid, compare_by_guid);
  /* In order to get this dissector from other dissectors */
  register_dissector("rtps", dissect_simple_rtps, proto_rtps);

  reassembly_table_register(&rtps_reassembly_table,
      &addresses_reassembly_table_functions);
}

void proto_reg_handoff_rtps(void) {
  heur_dissector_add("rtitcp", dissect_rtps_rtitcp, "RTPS over RTITCP", "rtps_rtitcp", proto_rtps, HEURISTIC_ENABLE);
  heur_dissector_add("udp", dissect_rtps_udp, "RTPS over UDP", "rtps_udp", proto_rtps, HEURISTIC_ENABLE);
  heur_dissector_add("tcp", dissect_rtps_tcp, "RTPS over TCP", "rtps_tcp", proto_rtps, HEURISTIC_ENABLE);
}

/*
 * Editor modelines
 *
 * Local Variables:
 * c-basic-offset: 2
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * ex: set shiftwidth=2 tabstop=8 expandtab:
 * :indentSize=2:tabSize=8:noTabs=true:
 */
