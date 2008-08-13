/* packet-rtps2.h
 * ~~~~~~~~~~~~~~
 *
 * Routines for Real-Time Publish-Subscribe Protocol (RTPS) dissection
 *
 * Copyright 2005, Fabrizio Bertocci <fabrizio@rti.com>
 * Real-Time Innovations, Inc.
 * 3975 Freedom Circle
 * Santa Clara, CA 95054
 *
 * $Id$
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@ethereal.com>
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
 *   Full OMG DDS Standard Specification: 
 *                             http://www.omg.org/cgi-bin/doc?ptc/2003-07-07
 *   
 *   RTI DDS and RTPS information: http://www.rti.com/resources.html
 *
 */


/* Note: This file is only included from packet-rtps2.c, so there is no risk
 * of namespace conflicts with all those macros.
 */
 
#ifndef _TYPEDEFS_DEFINES_RTPS2_H
#define _TYPEDEFS_DEFINES_RTPS2_H

#ifdef __cplusplus
extern "C" {
#endif


typedef enum {
    RTI_CDR_TK_NULL,
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
    RTI_CDR_TK_VALUE
} RTICdrTCKind;



/* Traffic type */
#define PORT_BASE                       (7400)
#define PORT_METATRAFFIC_UNICAST        (0)
#define PORT_USERTRAFFIC_MULTICAST      (1)
#define PORT_METATRAFFIC_MULTICAST      (2)
#define PORT_USERTRAFFIC_UNICAST        (3)

/* Flags defined in the 'flag' bitmask of a submessage */
#define FLAG_E                  (0x01)  /* Common to all the submessages */
#define FLAG_DATA_Q             (0x02)
#define FLAG_DATA_D             (0x04)
#define FLAG_DATA_H             (0x08)
#define FLAG_DATA_I             (0x10)

#define FLAG_DATA_FRAG_Q        (0x02)
#define FLAG_DATA_FRAG_H        (0x04)


#define FLAG_NOKEY_DATA_Q       (0x02)
#define FLAG_NOKEY_DATA_D       (0x04)
#define FLAG_NOKEY_DATA_FRAG_Q  (0x02)
#define FLAG_NOKEY_DATA_FRAG_D  (0x04)
#define FLAG_ACKNACK_F          (0x02)

#define FLAG_HEARTBEAT_F        (0x02)
#define FLAG_HEARTBEAT_L        (0x04)

#define FLAG_INFO_TS_T          (0x02)

#define FLAG_INFO_REPLY_IP4_M   (0x02)

#define FLAG_INFO_REPLY_M       (0x02)

#define FLAG_RTPS_DATA_Q        (0x02)
#define FLAG_RTPS_DATA_D        (0x04)

#define FLAG_RTPS_DATA_FRAG_Q   (0x02)

#define FLAG_RTPS_DATA_BATCH_Q  (0x02)

#define FLAG_SAMPLE_INFO_T      (0x01)
#define FLAG_SAMPLE_INFO_Q      (0x02)
#define FLAG_SAMPLE_INFO_O      (0x04)
#define FLAG_SAMPLE_INFO_D      (0x08)
#define FLAG_SAMPLE_INFO_I      (0x10)


/* The following PIDs are defined since RTPS 1.0 */
#define PID_PAD                                 (0x0000)
#define PID_SENTINEL                            (0x0001)
#define PID_PARTICIPANT_LEASE_DURATION          (0x0002)
#define PID_TIME_BASED_FILTER                   (0x0004)
#define PID_TOPIC_NAME                          (0x0005)
#define PID_OWNERSHIP_STRENGTH                  (0x0006)
#define PID_TYPE_NAME                           (0x0007)
#define PID_METATRAFFIC_MULTICAST_IPADDRESS     (0x000b)
#define PID_DEFAULT_UNICAST_IPADDRESS           (0x000c)
#define PID_METATRAFFIC_UNICAST_PORT            (0x000d)
#define PID_DEFAULT_UNICAST_PORT                (0x000e)
#define PID_MULTICAST_IPADDRESS                 (0x0011)
#define PID_PROTOCOL_VERSION                    (0x0015)
#define PID_VENDOR_ID                           (0x0016)
#define PID_RELIABILITY                         (0x001a)
#define PID_LIVELINESS                          (0x001b)
#define PID_DURABILITY                          (0x001d)
#define PID_DURABILITY_SERVICE                  (0x001e)
#define PID_OWNERSHIP                           (0x001f)
#define PID_PRESENTATION                        (0x0021)
#define PID_DEADLINE                            (0x0023)
#define PID_DESTINATION_ORDER                   (0x0025)
#define PID_LATENCY_BUDGET                      (0x0027)
#define PID_PARTITION                           (0x0029)
#define PID_LIFESPAN                            (0x002b)
#define PID_USER_DATA                           (0x002c)
#define PID_GROUP_DATA                          (0x002d)
#define PID_TOPIC_DATA                          (0x002e)
#define PID_UNICAST_LOCATOR                     (0x002f)
#define PID_MULTICAST_LOCATOR                   (0x0030)
#define PID_DEFAULT_UNICAST_LOCATOR             (0x0031)
#define PID_METATRAFFIC_UNICAST_LOCATOR         (0x0032)
#define PID_METATRAFFIC_MULTICAST_LOCATOR       (0x0033)
#define PID_PARTICIPANT_MANUAL_LIVELINESS_COUNT (0x0034)
#define PID_CONTENT_FILTER_PROPERTY             (0x0035)
#define PID_PROPERTY_LIST_OLD                   (0x0036)        /* For compatibility between 4.2d and 4.2e */
#define PID_HISTORY                             (0x0040)
#define PID_RESOURCE_LIMIT                      (0x0041)
#define PID_EXPECTS_INLINE_QOS                  (0x0043)
#define PID_PARTICIPANT_BUILTIN_ENDPOINTS       (0x0044)
#define PID_METATRAFFIC_UNICAST_IPADDRESS       (0x0045)
#define PID_METATRAFFIC_MULTICAST_PORT          (0x0046)
#define PID_DEFAULT_MULTICAST_LOCATOR           (0x0048)
#define PID_TRANSPORT_PRIORITY                  (0x0049)
#define PID_PARTICIPANT_GUID                    (0x0050)
#define PID_PARTICIPANT_ENTITY_ID               (0x0051)
#define PID_GROUP_GUID                          (0x0052)
#define PID_GROUP_ENTITY_ID                     (0x0053)
#define PID_CONTENT_FILTER_INFO                 (0x0055)
#define PID_COHERENT_SET                        (0x0056)
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
#define PID_TYPECODE                            (0x8004)        /* Was: 0x47 in RTPS 1.2 */

/* The following QoS are deprecated (used in RTPS 1.0 and older) */
#define PID_PERSISTENCE                         (0x0003)
#define PID_TYPE_CHECKSUM                       (0x0008)
#define PID_TYPE2_NAME                          (0x0009)
#define PID_TYPE2_CHECKSUM                      (0x000a)
#define PID_IS_RELIABLE                         (0x000f)
#define PID_EXPECTS_ACK                         (0x0010)
#define PID_MANAGER_KEY                         (0x0012)
#define PID_SEND_QUEUE_SIZE                     (0x0013)
#define PID_RECV_QUEUE_SIZE                     (0x0018)
#define PID_VARGAPPS_SEQUENCE_NUMBER_LAST       (0x0017)
#define PID_RELIABILITY_ENABLED                 (0x0014)
#define PID_RELIABILITY_OFFERED                 (0x0019)
#define PID_LIVELINESS_OFFERED                  (0x001c)
#define PID_OWNERSHIP_OFFERED                   (0x0020)
#define PID_PRESENTATION_OFFERED                (0x0022)
#define PID_DEADLINE_OFFERED                    (0x0024)
#define PID_DESTINATION_ORDER_OFFERED           (0x0026)
#define PID_LATENCY_BUDGET_OFFERED              (0x0028)
#define PID_PARTITION_OFFERED                   (0x002a)



/* appId.appKind possible values */
#define APPKIND_UNKNOWN                         (0x00)
#define APPKIND_MANAGED_APPLICATION             (0x01)
#define APPKIND_MANAGER                         (0x02)



/* Predefined EntityIds */
#define ENTITYID_UNKNOWN                                (0x00000000)
#define ENTITYID_PARTICIPANT                            (0x000001c1)
#define ENTITYID_SEDP_BUILTIN_TOPIC_WRITER              (0x000002c2)        /* Was: ENTITYID_BUILTIN_TOPIC_WRITER */
#define ENTITYID_SEDP_BUILTIN_TOPIC_READER              (0x000002c7)        /* Was: ENTITYID_BUILTIN_TOPIC_READER */
#define ENTITYID_SEDP_BUILTIN_PUBLICATIONS_WRITER       (0x000003c2)        /* Was: ENTITYID_BUILTIN_PUBLICATIONS_WRITER */
#define ENTITYID_SEDP_BUILTIN_PUBLICATIONS_READER       (0x000003c7)        /* Was: ENTITYID_BUILTIN_PUBLICATIONS_READER */
#define ENTITYID_SEDP_BUILTIN_SUBSCRIPTIONS_WRITER      (0x000004c2)        /* Was: ENTITYID_BUILTIN_SUBSCRIPTIONS_WRITER */
#define ENTITYID_SEDP_BUILTIN_SUBSCRIPTIONS_READER      (0x000004c7)        /* Was: ENTITYID_BUILTIN_SUBSCRIPTIONS_READER */
#define ENTITYID_SPDP_BUILTIN_PARTICIPANT_WRITER        (0x000100c2)        /* Was: ENTITYID_BUILTIN_SDP_PARTICIPANT_WRITER */
#define ENTITYID_SPDP_BUILTIN_PARTICIPANT_READER        (0x000100c7)        /* Was: ENTITYID_BUILTIN_SDP_PARTICIPANT_READER */
#define ENTITYID_P2P_BUILTIN_PARTICIPANT_MESSAGE_WRITER (0x000200c2)
#define ENTITYID_P2P_BUILTIN_PARTICIPANT_MESSAGE_READER (0x000200c7)


/* Deprecated EntityId */
#define ENTITYID_APPLICATIONS_WRITER                    (0x000001c2)
#define ENTITYID_APPLICATIONS_READER                    (0x000001c7)
#define ENTITYID_CLIENTS_WRITER                         (0x000005c2)
#define ENTITYID_CLIENTS_READER                         (0x000005c7)
#define ENTITYID_SERVICES_WRITER                        (0x000006c2)
#define ENTITYID_SERVICES_READER                        (0x000006c7)
#define ENTITYID_MANAGERS_WRITER                        (0x000007c2)
#define ENTITYID_MANAGERS_READER                        (0x000007c7)
#define ENTITYID_APPLICATION_SELF                       (0x000008c1)
#define ENTITYID_APPLICATION_SELF_WRITER                (0x000008c2)
#define ENTITYID_APPLICATION_SELF_READER                (0x000008c7)

/* Predefined Entity Kind */
#define ENTITYKIND_APPDEF_UNKNOWN                       (0x00)
#define ENTITYKIND_APPDEF_PARTICIPANT                   (0x01)
#define ENTITYKIND_APPDEF_WRITER_WITH_KEY               (0x02)
#define ENTITYKIND_APPDEF_WRITER_NO_KEY                 (0x03)
#define ENTITYKIND_APPDEF_READER_NO_KEY                 (0x04)
#define ENTITYKIND_APPDEF_READER_WITH_KEY               (0x07)
#define ENTITYKIND_BUILTIN_PARTICIPANT                  (0xc1)
#define ENTITYKIND_BUILTIN_WRITER_WITH_KEY              (0xc2)
#define ENTITYKIND_BUILTIN_WRITER_NO_KEY                (0xc3)
#define ENTITYKIND_BUILTIN_READER_NO_KEY                (0xc4)
#define ENTITYKIND_BUILTIN_READER_WITH_KEY              (0xc7)


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

#define SUBMESSAGE_RTPS_DATA                            (0x15)  /* RTPS 2.1 only */
#define SUBMESSAGE_RTPS_DATA_FRAG                       (0x16)  /* RTPS 2.1 only */
#define SUBMESSAGE_ACKNACK_BATCH                        (0x17)  /* RTPS 2.1 only */
#define SUBMESSAGE_RTPS_DATA_BATCH                      (0x18)  /* RTPS 2.1 Only */
#define SUBMESSAGE_HEARTBEAT_BATCH                      (0x19)  /* RTPS 2.1 only */

/* Data encapsulation */
#define ENCAPSULATION_CDR_BE            (0x0000)
#define ENCAPSULATION_CDR_LE            (0x0001)
#define ENCAPSULATION_PL_CDR_BE         (0x0002)
#define ENCAPSULATION_PL_CDR_LE         (0x0003)


/* An invalid IP Address: 
 * Make sure the _STRING macro is bigger than a normal IP
 */
#define IPADDRESS_INVALID               (0)
#define IPADDRESS_INVALID_STRING        "ADDRESS_INVALID (0x00000000)"

/* Identifies the value of an invalid port number:
 * Make sure the _STRING macro is bigger than a normal port
 */
#define PORT_INVALID                    (0)
#define PORT_INVALID_STRING             "PORT_INVALID"

/* Protocol Vendor Information (guint16) */
#define RTPS_VENDOR_UNKNOWN             (0x0000)
#define RTPS_VENDOR_UNKNOWN_STRING      "VENDOR_ID_UNKNOWN (0x0000)"
#define RTPS_VENDOR_RTI                 (0x0101)
#define RTPS_VENDOR_RTI_STRING          "Real-Time Innovations, Inc."

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



#ifdef __cplusplus
} /* extern "C"*/
#endif
            
#endif /* _TYPEDEFS_DEFINES_RTPS2_H */
