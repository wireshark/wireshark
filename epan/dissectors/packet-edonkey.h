/* packet-edonkey.h
 * Declarations for edonkey dissection
 * Copyright 2003, Xuan Zhang <xz@aemail4u.com>
 * eDonkey dissector based on protocol descriptions from mldonkey:
 *  http://savannah.nongnu.org/download/mldonkey/docs/Edonkey-Overnet/edonkey-protocol.txt 
 *  http://savannah.nongnu.org/download/mldonkey/docs/Edonkey-Overnet/overnet-protocol.txt
 *
 * $Id$
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@ethereal.com>
 * Copyright 1998 Gerald Combs
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 */

void proto_register_edonkey(void);

#define EDONKEY_MAX_SNAP_SIZE	1500
#define EDONKEY_TCP_HEADER_LENGTH  5
#define EDONKEY_UDP_HEADER_LENGTH  2

/* Definitions for EDONKEY protocols */
#define EDONKEY_PROTO_EDONKEY        0xe3  /* eDonkey */
#define EDONKEY_PROTO_EMULE_EXT      0xc5  /* eMule extensions */
#define EDONKEY_PROTO_EMULE_COMP     0xd4  /* eMule compressed (data is zlib compressed) */

/* Definitions for EDONKEY messages */
/* EDONKEY TCP MESSAGES */
/* Client <-> Server */
#define EDONKEY_MSG_HELLO                0x01
#define EDONKEY_MSG_BAD_PROTO            0x05  
#define EDONKEY_MSG_GET_SERVER_LIST      0x14
#define EDONKEY_MSG_OFFER_FILES          0x15
#define EDONKEY_MSG_SEARCH_FILES         0x16
#define EDONKEY_MSG_DISCONNECT           0x18
#define EDONKEY_MSG_GET_SOURCES          0x19
#define EDONKEY_MSG_SEARCH_USER          0x1a
/* define EDONKEY_MSG_UNKNOWN            0x1b */
#define EDONKEY_MSG_CLIENT_CB_REQ        0x1c
/* define EDONKEY_MSG_UNKNOWN            0x20 */
#define EDONKEY_MSG_MORE_RESULTS         0x21
#define EDONKEY_MSG_SERVER_LIST          0x32
#define EDONKEY_MSG_SEARCH_FILE_RESULTS  0x33
#define EDONKEY_MSG_SERVER_STATUS        0x34
#define EDONKEY_MSG_SERVER_CB_REQ        0x35
#define EDONKEY_MSG_CALLBACK_FAIL        0x36
#define EDONKEY_MSG_SERVER_MESSAGE       0x38
#define EDONKEY_MSG_ID_CHANGE            0x40
#define EDONKEY_MSG_SERVER_INFO_DATA     0x41
#define EDONKEY_MSG_FOUND_SOURCES        0x42
#define EDONKEY_MSG_SEARCH_USER_RESULTS  0x43

/* Client <-> Client */
#define EDONKEY_MSG_HELLO_CLIENT         0x10 /* 0x01 0x10 */
#define EDONKEY_MSG_SENDING_PART         0x46 
#define EDONKEY_MSG_REQUEST_PARTS        0x47
#define EDONKEY_MSG_NO_SUCH_FILE         0x48
#define EDONKEY_MSG_END_OF_DOWNLOAD      0x49
#define EDONKEY_MSG_VIEW_FILES           0x4a
#define EDONKEY_MSG_VIEW_FILES_ANSWER    0x4b
#define EDONKEY_MSG_HELLO_ANSWER         0x4c
#define EDONKEY_MSG_NEW_CLIENT_ID        0x4d
#define EDONKEY_MSG_CLIENT_MESSAGE       0x4e
#define EDONKEY_MSG_FILE_STATUS_REQUEST  0x4f
#define EDONKEY_MSG_FILE_STATUS          0x50
#define EDONKEY_MSG_HASHSET_REQUEST      0x51
#define EDONKEY_MSG_HASHSET_ANSWER       0x52
/*#define EDONKEY_MSG_UNKNOWN              0x53 */
#define EDONKEY_MSG_SLOT_REQUEST         0x54
#define EDONKEY_MSG_SLOT_GIVEN           0x55
#define EDONKEY_MSG_SLOT_RELEASE         0x56
#define EDONKEY_MSG_SLOT_TAKEN           0x57
#define EDONKEY_MSG_FILE_REQUEST         0x58 
#define EDONKEY_MSG_FILE_REQUEST_ANSWER  0x59
/*#define EDONKEY_MSG_UNKNOWN              0x5b*/
#define EDONKEY_MSG_GET_SHARED_DIRS      0x5d
#define EDONKEY_MSG_GET_SHARED_FILES     0x5e
#define EDONKEY_MSG_SHARED_DIRS          0x5f
#define EDONKEY_MSG_SHARED_FILES         0x60
#define EDONKEY_MSG_SHARED_DENIED        0x61

/* OVERNET EXTENSIONS */
/*#define OVERNET_MSG_UNKNOWN              0x62*/
/*#define OVERNET_MSG_UNKNOWN              0x63*/

/* EMULE EXTENSIONS */
#define EMULE_MSG_HELLO                  0x01
#define EMULE_MSG_HELLO_ANSWER           0x02
#define EMULE_MSG_DATA_COMPRESSED        0x40
#define EMULE_MSG_QUEUE_RANKING          0x60
#define EMULE_MSG_SOURCES_REQUEST        0x81
#define EMULE_MSG_SOURCES_ANSWER         0x82

/* EDONKEY UDP MESSAGES */
#define EDONKEY_MSG_UDP_SERVER_STATUS_REQUEST      0x96
#define EDONKEY_MSG_UDP_SERVER_STATUS              0x97
#define EDONKEY_MSG_UDP_SEARCH_FILE                0x98
#define EDONKEY_MSG_UDP_SEARCH_FILE_RESULTS        0x99
#define EDONKEY_MSG_UDP_GET_SOURCES                0x9a
#define EDONKEY_MSG_UDP_FOUND_SOURCES              0x9b
#define EDONKEY_MSG_UDP_CALLBACK_REQUEST           0x9c
#define EDONKEY_MSG_UDP_CALLBACK_FAIL              0x9e
/* #define EDONKEY_MSG_UDP_UNKNOWN                    0xa0 */
#define EDONKEY_MSG_UDP_SERVER_LIST                0xa1
#define EDONKEY_MSG_UDP_GET_SERVER_INFO            0xa2
#define EDONKEY_MSG_UDP_SERVER_INFO                0xa3
#define EDONKEY_MSG_UDP_GET_SERVER_LIST            0xa4

/* EMULE UDP EXTENSIONS */
#define EMULE_MSG_UDP_REASKFILEPING      0x90
#define EMULE_MSG_UDP_REASKACK           0x91
#define EMULE_MSG_UDP_FILE_NOT_FOUND     0x92
#define EMULE_MSG_UDP_QUEUE_FULL         0x93

/* OVERNET UDP EXTENSIONS */
#define OVERNET_MSG_UDP_CONNECT                     0x0a
#define OVERNET_MSG_UDP_CONNECT_REPLY               0x0b
#define OVERNET_MSG_UDP_PUBLICIZE                   0x0c
#define OVERNET_MSG_UDP_PUBLICIZE_ACK               0x0d
#define OVERNET_MSG_UDP_SEARCH                      0x0e
#define OVERNET_MSG_UDP_SEARCH_NEXT                 0x0f
#define OVERNET_MSG_UDP_SEARCH_INFO                 0x10
#define OVERNET_MSG_UDP_SEARCH_RESULT               0x11
#define OVERNET_MSG_UDP_SEARCH_END                  0x12
#define OVERNET_MSG_UDP_PUBLISH                     0x13
#define OVERNET_MSG_UDP_PUBLISH_ACK                 0x14
#define OVERNET_MSG_UDP_IDENTIFY_REPLY              0x15
#define OVERNET_MSG_UDP_IDENTIFY_ACK                0x16
#define OVERNET_MSG_UDP_FIREWALL_CONNECTION         0x18
#define OVERNET_MSG_UDP_FIREWALL_CONNECTION_ACK     0x19
#define OVERNET_MSG_UDP_FIREWALL_CONNECTION_NACK    0x1a
#define OVERNET_MSG_UDP_IP_QUERY                    0x1b 
#define OVERNET_MSG_UDP_IP_QUERY_ANSWER             0x1c 
#define OVERNET_MSG_UDP_IP_QUERY_END                0x1d 
#define OVERNET_MSG_UDP_IDENTIFY                    0x1e 
/*#define OVERNET_MSG_UDP_UNKNOWN                    0x21  */

/* EDONKEY META TAG TYPES */
#define EDONKEY_MTAG_UNKNOWN             0x00
#define EDONKEY_MTAG_HASH                0x01
#define EDONKEY_MTAG_STRING              0x02
#define EDONKEY_MTAG_DWORD               0x03
#define EDONKEY_MTAG_FLOAT               0x04
#define EDONKEY_MTAG_BOOL                0x05
#define EDONKEY_MTAG_BOOL_ARRAY          0x06
#define EDONKEY_MTAG_BLOB                0x07
#define EDONKEY_MTAG_WORD                0x08
#define EDONKEY_MTAG_BYTE                0x09
#define EDONKEY_MTAG_BSOB                0x0a
#define EDONKEY_MTAG_STR1                0x11
#define EDONKEY_MTAG_STR16               0x20
#define EDONKEY_MTAG_SHORTNAME           0x80

/* EDONKEY SPECIAL TAGS */
#define EDONKEY_STAG_UNKNOWN             0x00
#define EDONKEY_STAG_NAME                0x01
#define EDONKEY_STAG_SIZE                0x02
#define EDONKEY_STAG_TYPE                0x03
#define EDONKEY_STAG_FORMAT              0x04
#define EDONKEY_STAG_COLLECTION          0x05
#define EDONKEY_STAG_PART_PATH           0x06
#define EDONKEY_STAG_PART_HASH           0x07
#define EDONKEY_STAG_COPIED              0x08
#define EDONKEY_STAG_GAP_START           0x09
#define EDONKEY_STAG_GAP_END             0x0a
#define EDONKEY_STAG_DESCRIPTION         0x0b
#define EDONKEY_STAG_PING                0x0c
#define EDONKEY_STAG_FAIL                0x0d
#define EDONKEY_STAG_PREFERENCE          0x0e
#define EDONKEY_STAG_PORT                0x0f
#define EDONKEY_STAG_IP                  0x10
#define EDONKEY_STAG_VERSION             0x11
#define EDONKEY_STAG_TEMPFILE            0x12
#define EDONKEY_STAG_PRIORITY            0x13
#define EDONKEY_STAG_STATUS              0x14
#define EDONKEY_STAG_AVAILABILITY        0x15
#define EDONKEY_STAG_QTIME               0x16
#define EDONKEY_STAG_PARTS               0x17
#define EDONKEY_STAG_MOD_VERSION         0x55

/* EMULE SPECIAL TAGS */
#define EMULE_STAG_COMPRESSION         0x20
#define EMULE_STAG_UDP_CLIENT_PORT     0x21
#define EMULE_STAG_UDP_VERSION         0x22
#define EMULE_STAG_SOURCE_EXCHANGE     0x23
#define EMULE_STAG_COMMENTS            0x24
#define EMULE_STAG_EXTENDED_REQUEST    0x25
#define EMULE_STAG_COMPATIBLE_CLIENT   0x26
#define EMULE_STAG_COMPAT_OPTIONS1     0xef
#define EMULE_STAG_UDPPORTS            0xf9
#define EMULE_STAG_MISCOPTIONS1        0xfa
#define EMULE_STAG_VERSION             0xfb
#define EMULE_STAG_BUDDYIP             0xfc
#define EMULE_STAG_BUDDYUDP            0xfd
#define EMULE_STAG_MISCOPTIONS2        0xfe

/* EDONKEY SEARCH TYPES */
#define EDONKEY_SEARCH_BOOL              0x00
#define EDONKEY_SEARCH_NAME              0x01
#define EDONKEY_SEARCH_META              0x02
#define EDONKEY_SEARCH_LIMIT             0x03

/* EDONKEY SEARCH OPERATORS */
#define EDONKEY_SEARCH_AND               0x00
#define EDONKEY_SEARCH_OR                0x01
#define EDONKEY_SEARCH_ANDNOT            0x02

/* EDONKEY SEARCH MIN/MAX   */
#define EDONKEY_SEARCH_MIN               0x01
#define EDONKEY_SEARCH_MAX               0x02
