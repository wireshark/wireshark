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
#define FLAG_DATA_D             (0x02)
#define FLAG_DATA_A             (0x04)
#define FLAG_DATA_H             (0x08)
#define FLAG_DATA_Q             (0x10)
#define FLAG_DATA_U             (0x20)
#define FLAG_NOKEY_DATA_Q       (0x02)
#define FLAG_NOKEY_DATA_D       (0x04)
#define FLAG_ACKNACK_F          (0x02)
#define FLAG_HEARTBEAT_F        (0x02)
#define FLAG_GAP_F              (0x02)
#define FLAG_INFO_TS_T          (0x02)
#define FLAG_INFO_REPLY_IP4_M   (0x02)
#define FLAG_INFO_REPLY_M       (0x02)



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
#define PID_PROPERTY_LIST                       (0x36)
#define PID_HISTORY                             (0x40)
#define PID_RESOURCE_LIMIT                      (0x41)
#define PID_DEFAULT_EXPECTS_INLINE_QOS          (0x43)
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
#define PID_RELIABILITY_OFFERED                 (0x19)
#define PID_LIVELINESS_OFFERED                  (0x1c)
#define PID_OWNERSHIP_OFFERED                   (0x20)
#define PID_PRESENTATION_OFFERED                (0x22)
#define PID_DEADLINE_OFFERED                    (0x24)
#define PID_DESTINATION_ORDER_OFFERED           (0x26)
#define PID_LATENCY_BUDGET_OFFERED              (0x28)
#define PID_PARTITION_OFFERED                   (0x2a)
#define PID_PERSISTENCE                         (0x03)
#define PID_TYPE_CHECKSUM                       (0x08)
#define PID_TYPE2_NAME                          (0x09)
#define PID_TYPE2_CHECKSUM                      (0x0a)
#define PID_IS_RELIABLE                         (0x0f)
#define PID_EXPECTS_ACK                         (0x10)
#define PID_MANAGER_KEY                         (0x12)
#define PID_SEND_QUEUE_SIZE                     (0x13)
#define PID_RECV_QUEUE_SIZE                     (0x18)
#define PID_VARGAPPS_SEQUENCE_NUMBER_LAST       (0x17)
#define PID_RELIABILITY_ENABLED                 (0x14)

/* appId.appKind possible values */
#define APPKIND_UNKNOWN                         (0x00)
#define APPKIND_MANAGED_APPLICATION             (0x01)
#define APPKIND_MANAGER                         (0x02)



/* Predefined EntityId */
#define ENTITYID_UNKNOWN                        (0x00000000)
#define ENTITYID_BUILTIN_TOPIC_WRITER           (0x000002c2)
#define ENTITYID_BUILTIN_TOPIC_READER           (0x000002c7)
#define ENTITYID_BUILTIN_PUBLICATIONS_WRITER    (0x000003c2)
#define ENTITYID_BUILTIN_PUBLICATIONS_READER    (0x000003c7)
#define ENTITYID_BUILTIN_SUBSCRIPTIONS_WRITER   (0x000004c2)
#define ENTITYID_BUILTIN_SUBSCRIPTIONS_READER   (0x000004c7)
#define ENTITYID_BUILTIN_SDP_PARTICIPANT_WRITER (0x000100c2)
#define ENTITYID_BUILTIN_SDP_PARTICIPANT_READER (0x000100c7)

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
#define PAD                             (0x01)
#define DATA                            (0x02)
#define NOKEY_DATA                      (0x03)
#define ACKNACK                         (0x06)
#define HEARTBEAT                       (0x07)
#define GAP                             (0x08)
#define INFO_TS                         (0x09)
#define INFO_SRC                        (0x0c)
#define INFO_REPLY_IP4                  (0x0d)
#define INFO_DST                        (0x0e)
#define INFO_REPLY                      (0x0f)



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







#ifdef __cplusplus
} /* extern "C"*/
#endif
            
#endif /* _TYPEDEFS_DEFINES_RTPS_H */
