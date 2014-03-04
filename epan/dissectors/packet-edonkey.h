/* packet-edonkey.h
 * Declarations for edonkey dissection
 * Copyright 2003, Xuan Zhang <xz@aemail4u.com>
 * Copyright 2007, Stefano Picerno <stefano.picerno@gmail.com>
 * Copyright 2008, Stefan Monhof <stefan.monhof@stud.uni-due.de>
 *
 * eDonkey dissector based on protocol descriptions from mldonkey:
 *  http://savannah.nongnu.org/download/mldonkey/docs/Edonkey-Overnet/edonkey-protocol.txt
 *  http://savannah.nongnu.org/download/mldonkey/docs/Edonkey-Overnet/overnet-protocol.txt
 *
 * Kademlia dissector based on source code inspection of aMule 2.1.3 and eMule 0.48a
 * Modified and added on the basis of information and names from the eMule 0.49a source code
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

void proto_register_edonkey(void);

#define EDONKEY_MAX_SNAP_SIZE   1500
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
#define EDONKEY_MSG_GET_SOURCES_OBFU     0x23
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
#define EDONKEY_MSG_FOUND_SOURCES_OBFU   0x44

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
#define EMULE_MSG_FILE_DESC              0x61
#define EMULE_MSG_SOURCES_REQUEST        0x81
#define EMULE_MSG_SOURCES_ANSWER         0x82
#define EMULE_MSG_PUBLIC_KEY             0x85
#define EMULE_MSG_SIGNATURE              0x86
#define EMULE_MSG_SEC_IDENT_STATE        0x87
#define EMULE_MSG_MULTIPACKET            0x92
#define EMULE_MSG_MULTIPACKET_ANSWER     0x93
#define EMULE_MSG_CALLBACK               0x99
#define EMULE_MSG_AICH_REQUEST           0x9b
#define EMULE_MSG_AICH_ANSWER            0x9c
#define EMULE_MSG_AICHFILEHASH_ANSWER    0x9d
#define EMULE_MSG_AICHFILEHASH_REQUEST   0x9e
#define EMULE_MSG_DATA_COMPRESSED_64     0xa1
#define EMULE_MSG_SENDING_PART_64        0xa2
#define EMULE_MSG_REQUEST_PARTS_64       0xa3
#define EMULE_MSG_MULTIPACKET_EXT        0xa4

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
#define EMULE_STAG_COMPLETE_SOURCES    0x30
#define EMULE_STAG_SIZE_HI             0x3a
#define EMULE_STAG_SERVER_VERSION      0x91
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

/* KADEMLIA TAGS */
#define KADEMLIA_TAGTYPE_HASH                   0x01
#define KADEMLIA_TAGTYPE_STRING                 0x02
#define KADEMLIA_TAGTYPE_UINT32                 0x03
#define KADEMLIA_TAGTYPE_FLOAT32                0x04
#define KADEMLIA_TAGTYPE_BOOL                   0x05
#define KADEMLIA_TAGTYPE_BOOLARRAY              0x06
#define KADEMLIA_TAGTYPE_BLOB                   0x07
#define KADEMLIA_TAGTYPE_UINT16                 0x08
#define KADEMLIA_TAGTYPE_UINT8                  0x09
#define KADEMLIA_TAGTYPE_BSOB                   0x0A
#define KADEMLIA_TAGTYPE_UINT64                 0x0B

#define KADEMLIA_TAGTYPE_STR1                   0x11
#define KADEMLIA_TAGTYPE_STR2                   0x12
#define KADEMLIA_TAGTYPE_STR3                   0x13
#define KADEMLIA_TAGTYPE_STR4                   0x14
#define KADEMLIA_TAGTYPE_STR5                   0x15
#define KADEMLIA_TAGTYPE_STR6                   0x16
#define KADEMLIA_TAGTYPE_STR7                   0x17
#define KADEMLIA_TAGTYPE_STR8                   0x18
#define KADEMLIA_TAGTYPE_STR9                   0x19
#define KADEMLIA_TAGTYPE_STR10                  0x1A
#define KADEMLIA_TAGTYPE_STR11                  0x1B
#define KADEMLIA_TAGTYPE_STR12                  0x1C
#define KADEMLIA_TAGTYPE_STR13                  0x1D
#define KADEMLIA_TAGTYPE_STR14                  0x1E
#define KADEMLIA_TAGTYPE_STR15                  0x1F
#define KADEMLIA_TAGTYPE_STR16                  0x20
#define KADEMLIA_TAGTYPE_STR17                  0x21
#define KADEMLIA_TAGTYPE_STR18                  0x22
#define KADEMLIA_TAGTYPE_STR19                  0x23
#define KADEMLIA_TAGTYPE_STR20                  0x24
#define KADEMLIA_TAGTYPE_STR21                  0x25
#define KADEMLIA_TAGTYPE_STR22                  0x26

#define KADEMLIA_TAG_MEDIA_ARTIST               0xD0    /* <string> */
#define KADEMLIA_TAG_MEDIA_ALBUM                0xD1    /* <string> */
#define KADEMLIA_TAG_MEDIA_TITLE                0xD2    /* <string> */
#define KADEMLIA_TAG_MEDIA_LENGTH               0xD3    /* <uint32> !!! */
#define KADEMLIA_TAG_MEDIA_BITRATE              0xD4    /* <uint32> */
#define KADEMLIA_TAG_MEDIA_CODEC                0xD5    /* <string> */
#define KADEMLIA_TAG_USER_COUNT                 0xF4    /* <uint32> */
#define KADEMLIA_TAG_FILE_COUNT                 0xF5    /* <uint32> */
#define KADEMLIA_TAG_FILECOMMENT                0xF6    /* <string> */
#define KADEMLIA_TAG_FILERATING                 0xF7    /* <uint8> */
#define KADEMLIA_TAG_BUDDYHASH                  0xF8    /* <string> */
#define KADEMLIA_TAG_CLIENTLOWID                0xF9    /* <uint32> */
#define KADEMLIA_TAG_SERVERPORT                 0xFA    /* <uint16> */
#define KADEMLIA_TAG_SERVERIP                   0xFB    /* <uint32> */
#define KADEMLIA_TAG_SOURCEUPORT                0xFC    /* <uint16> */
#define KADEMLIA_TAG_SOURCEPORT                 0xFD    /* <uint16> */
#define KADEMLIA_TAG_SOURCEIP                   0xFE    /* <uint32> */
#define KADEMLIA_TAG_SOURCETYPE                 0xFF    /* <uint8> */

#define EDONKEY_PROTO_ADU_KADEMLIA              0xA4
#define EDONKEY_PROTO_ADU_KADEMLIA_COMP         0xA5

#define EDONKEY_PROTO_KADEMLIA                  0xE4
#define EDONKEY_PROTO_KADEMLIA_COMP             0xE5

/* KADEMLIA (opcodes) (udp) */
#define KADEMLIA_BOOTSTRAP_REQ                  0x00    /* <PEER (sender) [25]> */
#define KADEMLIA2_BOOTSTRAP_REQ                 0x01   /*  */

#define KADEMLIA_BOOTSTRAP_RES                  0x08    /* <CNT [2]> <PEER [25]>*(CNT) */
#define KADEMLIA2_BOOTSTRAP_RES                 0x09   /*  */

#define KADEMLIA_HELLO_REQ                      0x10    /* <PEER (sender) [25]> */
#define KADEMLIA2_HELLO_REQ                     0x11   /*  */

#define KADEMLIA_HELLO_RES                      0x18    /* <PEER (receiver) [25]> */
#define KADEMLIA2_HELLO_RES                     0x19   /*  */

#define KADEMLIA_REQ                            0x20    /* <TYPE [1]> <HASH (target) [16]> <HASH (receiver) 16> */
#define KADEMLIA2_REQ                           0x21   /*  */

#define KADEMLIA_RES                            0x28    /* <HASH (target) [16]> <CNT> <PEER [25]>*(CNT) */
#define KADEMLIA2_RES                           0x29   /*  */

#define KADEMLIA_SEARCH_REQ                     0x30    /* <HASH (key) [16]> <ext 0/1 [1]> <SEARCH_TREE>[ext] */
/*#define UNUSED                                0x31    Old Opcode, don't use. */
#define KADEMLIA_SEARCH_NOTES_REQ               0x32    /* <HASH (key) [16]> */
#define KADEMLIA2_SEARCH_KEY_REQ                0x33   /*  */
#define KADEMLIA2_SEARCH_SOURCE_REQ             0x34   /*  */
#define KADEMLIA2_SEARCH_NOTES_REQ              0x35   /*  */

#define KADEMLIA_SEARCH_RES                     0x38    /* <HASH (key) [16]> <CNT1 [2]> (<HASH (answer) [16]> <CNT2 [2]> <META>*(CNT2))*(CNT1) */
/*#define UNUSED                                0x39    Old Opcode, don't use. */
#define KADEMLIA_SEARCH_NOTES_RES               0x3A    /* <HASH (key) [16]> <CNT1 [2]> (<HASH (answer) [16]> <CNT2 [2]> <META>*(CNT2))*(CNT1) */
#define KADEMLIA2_SEARCH_RES                    0x3B   /*  */

#define KADEMLIA_PUBLISH_REQ                    0x40    /* <HASH (key) [16]> <CNT1 [2]> (<HASH (target) [16]> <CNT2 [2]> <META>*(CNT2))*(CNT1) */
/*#define UNUSED                                0x41    Old Opcode, don't use. */
#define KADEMLIA_PUBLISH_NOTES_REQ              0x42    /* <HASH (key) [16]> <HASH (target) [16]> <CNT2 [2]> <META>*(CNT2))*(CNT1) */
#define KADEMLIA2_PUBLISH_KEY_REQ               0x43   /*  */
#define KADEMLIA2_PUBLISH_SOURCE_REQ            0x44   /*  */
#define KADEMLIA2_PUBLISH_NOTES_REQ             0x45   /*  */

#define KADEMLIA_PUBLISH_RES                    0x48    /* <HASH (key) [16]> */
/*#define UNUSED                                0x49    Old Opcode, don't use. */
#define KADEMLIA_PUBLISH_NOTES_RES              0x4A    /* <HASH (key) [16]> */
#define KADEMLIA2_PUBLISH_RES                   0x4B   /*  */

#define KADEMLIA_FIREWALLED_REQ                 0x50    /* <TCPPORT (sender) [2]> */
#define KADEMLIA_FINDBUDDY_REQ                  0x51    /* <TCPPORT (sender) [2]> */
#define KADEMLIA_CALLBACK_REQ                   0x52    /* <TCPPORT (sender) [2]> */

#define KADEMLIA_FIREWALLED_RES                 0x58    /* <IP (sender) [4]> */
#define KADEMLIA_FIREWALLED_ACK_RES             0x59    /* (null) */
#define KADEMLIA_FINDBUDDY_RES                  0x5A    /* <TCPPORT (sender) [2]> */

/* KADEMLIA (parameter) */
#define KADEMLIA_FIND_VALUE                     0x02
#define KADEMLIA_STORE                          0x04
#define KADEMLIA_FIND_NODE                      0x0B

/* Kad search + some unused tags to mirror the ed2k ones. */
#define KADEMLIA_TAG_FILENAME                   0x01    /* <string> */
#define KADEMLIA_TAG_FILESIZE                   0x02    /* <uint32> */
#define KADEMLIA_TAG_FILESIZE_HI                0x3A    /* <uint32> */
#define KADEMLIA_TAG_FILETYPE                   0x03    /* <string> */
#define KADEMLIA_TAG_FILEFORMAT                 0x04    /* <string> */
#define KADEMLIA_TAG_COLLECTION                 0x05
#define KADEMLIA_TAG_PART_PATH                  0x06    /* <string> */
#define KADEMLIA_TAG_PART_HASH                  0x07
#define KADEMLIA_TAG_COPIED                     0x08    /* <uint32> */
#define KADEMLIA_TAG_GAP_START                  0x09    /* <uint32> */
#define KADEMLIA_TAG_GAP_END                    0x0A    /* <uint32> */
#define KADEMLIA_TAG_DESCRIPTION                0x0B    /* <string> */
#define KADEMLIA_TAG_PING                       0x0C
#define KADEMLIA_TAG_FAIL                       0x0D
#define KADEMLIA_TAG_PREFERENCE                 0x0E
#define KADEMLIA_TAG_PORT                       0x0F
#define KADEMLIA_TAG_IP_ADDRESS                 0x10
#define KADEMLIA_TAG_VERSION                    0x11    /* <string> */
#define KADEMLIA_TAG_TEMPFILE                   0x12    /* <string> */
#define KADEMLIA_TAG_PRIORITY                   0x13    /* <uint32> */
#define KADEMLIA_TAG_STATUS                     0x14    /* <uint32> */
#define KADEMLIA_TAG_SOURCES                    0x15    /* <uint32> */
#define KADEMLIA_TAG_PERMISSIONS                0x16
#define KADEMLIA_TAG_QTIME                      0x16
#define KADEMLIA_TAG_PARTS                      0x17
#define KADEMLIA_TAG_MEDIA_ARTIST               0xD0    /* <string> */
#define KADEMLIA_TAG_MEDIA_ALBUM                0xD1    /* <string> */
#define KADEMLIA_TAG_MEDIA_TITLE                0xD2    /* <string> */
#define KADEMLIA_TAG_MEDIA_LENGTH               0xD3    /* <uint32> !!! */
#define KADEMLIA_TAG_MEDIA_BITRATE              0xD4    /* <uint32> */
#define KADEMLIA_TAG_MEDIA_CODEC                0xD5    /* <string> */
#define KADEMLIA_TAG_ENCRYPTION                 0xF3    /* <uint8> */
#define KADEMLIA_TAG_FILERATING                 0xF7    /* <uint8> */
#define KADEMLIA_TAG_BUDDYHASH                  0xF8    /* <string> */
#define KADEMLIA_TAG_CLIENTLOWID                0xF9    /* <uint32> */
#define KADEMLIA_TAG_SERVERPORT                 0xFA    /* <uint16> */
#define KADEMLIA_TAG_SERVERIP                   0xFB    /* <uint32> */
#define KADEMLIA_TAG_SOURCEUPORT                0xFC    /* <uint16> */
#define KADEMLIA_TAG_SOURCEPORT                 0xFD    /* <uint16> */
#define KADEMLIA_TAG_SOURCEIP                   0xFE    /* <uint32> */
#define KADEMLIA_TAG_SOURCETYPE                 0xFF    /* <uint8> */

/* KADEMLIA (version) */
#define KADEMLIA_VERSION1_46c			0x01   /*45b - 46c*/
#define KADEMLIA_VERSION2_47a			0x02   /*47a*/
#define KADEMLIA_VERSION3_47b			0x03   /*47b*/
#define KADEMLIA_VERSION5_48a			0x05   /* -0.48a */
#define KADEMLIA_VERSION6_49aBETA		0x06   /* -0.49aBETA1 */
#define KADEMLIA_VERSION7_49a			0x07   /* -0.49a */
