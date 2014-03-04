/* packet-rtps.h
 * ~~~~~~~~~~~~~
 *
 * Routines for Real-Time Publish-Subscribe Protocol (RTPS) dissection
 *
 * Copyright 2005, Fabrizio Bertocci <fabrizio@rti.com>
 * Real-Time Innovations, Inc.
 * 385 Moffett Park Drive, Suite 115
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

#ifndef _TYPEDEFS_DEFINES_RTPS_H
#define _TYPEDEFS_DEFINES_RTPS_H

#ifdef __cplusplus
extern "C" {
#endif


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
    RTI_CDR_TK_VALUE_PARARM
} RTICdrTCKind;

#define RTPS_MAGIC_NUMBER   0x52545053 /* RTPS */

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

/* The following QoS are deprecated */
#define PID_PERSISTENCE                         (0x03)
#define PID_TYPE_CHECKSUM                       (0x08)
#define PID_TYPE2_NAME                          (0x09)
#define PID_TYPE2_CHECKSUM                      (0x0a)
#define PID_IS_RELIABLE                         (0x0f)
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

/* Vendor-specific: RTI */
#define PID_PRODUCT_VERSION                     (0x8000)
#define PID_PLUGIN_PROMISCUITY_KIND             (0x8001)
#define PID_ENTITY_VIRTUAL_GUID                 (0x8002)
#define PID_SERVICE_KIND                        (0x8003)
#define PID_TYPECODE_RTPS2                      (0x8004)        /* Was: 0x47 in RTPS 1.2 */
#define PID_DISABLE_POSITIVE_ACKS               (0x8005)
#define PID_LOCATOR_FILTER_LIST                 (0x8006)

/* appId.appKind possible values */
#define APPKIND_UNKNOWN                         (0x00)
#define APPKIND_MANAGED_APPLICATION             (0x01)
#define APPKIND_MANAGER                         (0x02)



/* Predefined EntityId */
#define ENTITYID_UNKNOWN                        (0x00000000)
#define ENTITYID_PARTICIPANT                    (0x000001c1)
#define ENTITYID_BUILTIN_TOPIC_WRITER           (0x000002c2)
#define ENTITYID_BUILTIN_TOPIC_READER           (0x000002c7)
#define ENTITYID_BUILTIN_PUBLICATIONS_WRITER    (0x000003c2)
#define ENTITYID_BUILTIN_PUBLICATIONS_READER    (0x000003c7)
#define ENTITYID_BUILTIN_SUBSCRIPTIONS_WRITER   (0x000004c2)
#define ENTITYID_BUILTIN_SUBSCRIPTIONS_READER   (0x000004c7)
#define ENTITYID_BUILTIN_SDP_PARTICIPANT_WRITER (0x000100c2)
#define ENTITYID_BUILTIN_SDP_PARTICIPANT_READER (0x000100c7)
#define ENTITYID_P2P_BUILTIN_PARTICIPANT_MESSAGE_WRITER (0x000200c2)
#define ENTITYID_P2P_BUILTIN_PARTICIPANT_MESSAGE_READER (0x000200c7)

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

/* Protocol Vendor Information (guint16) */
#define RTPS_VENDOR_UNKNOWN              (0x0000)
#define RTPS_VENDOR_UNKNOWN_STRING       "VENDOR_ID_UNKNOWN (0x0000)"
#define RTPS_VENDOR_RTI_DDS              (0x0101)
#define RTPS_VENDOR_RTI_DDS_STRING       "Real-Time Innovations, Inc. - Connext DDS"
#define RTPS_VENDOR_PT_DDS               (0x0102)
#define RTPS_VENDOR_PT_DDS_STRING        "PrismTech Inc. - OpenSplice DDS"
#define RTPS_VENDOR_OCI                  (0x0103)
#define RTPS_VENDOR_OCI_STRING           "Object Computing Incorporated, Inc. (OCI) - OpenDDS"
#define RTPS_VENDOR_MILSOFT              (0x0104)
#define RTPS_VENDOR_MILSOFT_STRING       "MilSoft"
#define RTPS_VENDOR_GALLIUM              (0x0105)
#define RTPS_VENDOR_GALLIUM_STRING       "Gallium Visual Systems Inc. - InterCOM DDS"
#define RTPS_VENDOR_TOC                  (0x0106)
#define RTPS_VENDOR_TOC_STRING           "TwinOaks Computing, Inc. - CoreDX DDS"
#define RTPS_VENDOR_LAKOTA_TSI           (0x0107)
#define RTPS_VENDOR_LAKOTA_TSI_STRING    "Lakota Technical Solutions, Inc."
#define RTPS_VENDOR_ICOUP                (0x0108)
#define RTPS_VENDOR_ICOUP_STRING         "ICOUP Consulting"
#define RTPS_VENDOR_ETRI                 (0x0109)
#define RTPS_VENDOR_ETRI_STRING          "ETRI Electronics and Telecommunication Research Institute"
#define RTPS_VENDOR_RTI_DDS_MICRO        (0x010A)
#define RTPS_VENDOR_RTI_DDS_MICRO_STRING "Real-Time Innovations, Inc. (RTI) - Connext DDS Micro"
#define RTPS_VENDOR_PT_MOBILE            (0x010B)
#define RTPS_VENDOR_PT_MOBILE_STRING     "PrismTech - OpenSplice Mobile"
#define RTPS_VENDOR_PT_GATEWAY           (0x010C)
#define RTPS_VENDOR_PT_GATEWAY_STRING    "PrismTech - OpenSplice Gateway"
#define RTPS_VENDOR_PT_LITE              (0x010D)
#define RTPS_VENDOR_PT_LITE_STRING       "PrismTech - OpenSplice Lite"
#define RTPS_VENDOR_TECHNICOLOR          (0x010E)
#define RTPS_VENDOR_TECHNICOLOR_STRING   "Technicolor Inc. - Qeo"

/* Data encapsulation */
#define ENCAPSULATION_CDR_BE            (0x0000)
#define ENCAPSULATION_CDR_LE            (0x0001)
#define ENCAPSULATION_PL_CDR_BE         (0x0002)
#define ENCAPSULATION_PL_CDR_LE         (0x0003)

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

/* History Kind */
#define HISTORY_KIND_KEEP_LAST          (0)
#define HISTORY_KIND_KEEP_ALL           (1)

/* Reliability Values */
#define RELIABILITY_BEST_EFFORT         (1)
#define RELIABILITY_RELIABLE            (2)

/* Destination Order */
#define BY_RECEPTION_TIMESTAMP          (0)
#define BY_SOURCE_TIMESTAMP             (1)

/* Participant message data kind */
#define PARTICIPANT_MESSAGE_DATA_KIND_UNKNOWN (0x00000000)
#define PARTICIPANT_MESSAGE_DATA_KIND_AUTOMATIC_LIVELINESS_UPDATE (0x00000001)
#define PARTICIPANT_MESSAGE_DATA_KIND_MANUAL_LIVELINESS_UPDATE (0x00000002)

/* Utilities to add elements to the protocol tree for packet-rtps.h and packet-rtps2.h */
extern guint16 rtps_util_add_protocol_version(proto_tree *tree, tvbuff_t* tvb, gint offset);
extern guint16 rtps_util_add_vendor_id(proto_tree *tree, tvbuff_t * tvb, gint offset);
extern void rtps_util_add_locator_t(proto_tree *tree, packet_info *pinfo, tvbuff_t * tvb, gint offset,
                             gboolean little_endian, const guint8 * label);
extern int rtps_util_add_locator_list(proto_tree *tree, packet_info *pinfo, tvbuff_t * tvb,
                                gint offset, const guint8* label, gboolean little_endian);
extern void rtps_util_add_ipv4_address_t(proto_tree *tree, packet_info *pinfo, tvbuff_t * tvb, gint offset,
                                         gboolean little_endian, int hf_item);
extern void rtps_util_add_locator_udp_v4(proto_tree *tree, packet_info *pinfo, tvbuff_t * tvb,
                                  gint offset, const guint8 * label, gboolean little_endian);
extern int rtps_util_add_entity_id(proto_tree *tree, tvbuff_t * tvb, gint offset,
                            int hf_item, int hf_item_entity_key, int hf_item_entity_kind,
                            int subtree_entity_id, const char *label, guint32* entity_id_out);
extern void rtps_util_add_generic_entity_id(proto_tree *tree, tvbuff_t * tvb, gint offset, const char* label,
                                     int hf_item, int hf_item_entity_key, int hf_item_entity_kind,
                                     int subtree_entity_id);
extern guint64 rtps_util_add_seq_number(proto_tree *, tvbuff_t *,
                        gint, int, const char *);
extern void rtps_util_add_ntp_time(proto_tree *tree, tvbuff_t * tvb, gint offset,
                                   gboolean little_endian, int hf_time);
extern gint rtps_util_add_string(proto_tree *tree, tvbuff_t* tvb, gint offset,
                          int hf_item, gboolean little_endian);
extern void rtps_util_add_port(proto_tree *tree, packet_info *pinfo, tvbuff_t * tvb,
                        gint offset, gboolean little_endian, int hf_item);
extern void rtps_util_add_durability_service_qos(proto_tree *tree, tvbuff_t * tvb,
                                                 gint offset, gboolean little_endian);
extern void rtps_util_add_liveliness_qos(proto_tree *tree, tvbuff_t * tvb, gint offset,
                                         gboolean little_endian);
extern gint rtps_util_add_seq_string(proto_tree *tree, tvbuff_t* tvb, gint offset,
                              gboolean little_endian, int param_length, int hf_numstring,
                              int hf_string, const char *label);
extern void rtps_util_add_seq_octets(proto_tree *tree, packet_info *pinfo, tvbuff_t* tvb,
                              gint offset, gboolean little_endian, int param_length, int hf_id);
extern gint rtps_util_add_seq_ulong(proto_tree *tree, tvbuff_t * tvb, gint offset, int hf_item,
                        gboolean little_endian, int param_length, const char *label);

extern gboolean rtps_is_ping(tvbuff_t *tvb, packet_info *pinfo, gint offset);

/* Shared submessage dissection */
extern void dissect_PAD(tvbuff_t *tvb, packet_info *pinfo, gint offset, guint8 flags,
                        gboolean little_endian, int octects_to_next_header, proto_tree *tree);
extern void dissect_INFO_SRC(tvbuff_t *tvb, packet_info *pinfo, gint offset, guint8 flags,
                        gboolean little_endian, int octets_to_next_header, proto_tree *tree, guint16 rtps_version);
extern void dissect_INFO_TS(tvbuff_t *tvb, packet_info *pinfo, gint offset, guint8 flags,
                        gboolean little_endian, int octets_to_next_header, proto_tree *tree);


#ifdef __cplusplus
} /* extern "C"*/
#endif

#endif /* _TYPEDEFS_DEFINES_RTPS_H */
