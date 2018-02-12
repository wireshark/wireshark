/* packet-rmi.h
 * header file for java rmiregistry dissection
 * Copyright 2002, Michael Stiller <ms@2scale.net>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#ifndef __PACKET_RMI_H__
#define __PACKET_RMI_H__

#define SER_STREAM_MAGIC   0xaced

#define SER_STREAM_VERSION 5

#define SER_TC_NULL		0x70
#define SER_TC_REFERENCE	0x71
#define SER_TC_CLASSDESC	0x72
#define SER_TC_OBJECT		0x73
#define SER_TC_STRING		0x74
#define SER_TC_ARRAY		0x75
#define SER_TC_CLASS		0x76
#define SER_TC_BLOCKDATA	0x77
#define SER_TC_ENDBLOCKDATA	0x78
#define SER_TC_RESET		0x79
#define SER_TC_BLOCKDATALONG   	0x7A
#define SER_TC_EXCEPTION   	0x7B

#define RMI_MAGIC               "JRMI"
#define RMI_MAGIC_HEX           0x4a524d49

#define RMI_OUTPUTSTREAM_PROTOCOL_STREAM     0x4b
#define RMI_OUTPUTSTREAM_PROTOCOL_SINGLEOP   0x4c
#define RMI_OUTPUTSTREAM_PROTOCOL_MULTIPLEX  0x4d

#define RMI_OUTPUTSTREAM_MESSAGE_CALL        0x50
#define RMI_OUTPUTSTREAM_MESSAGE_PING        0x52
#define RMI_OUTPUTSTREAM_MESSAGE_DGCACK      0x54

#define RMI_INPUTSTREAM_MESSAGE_ACK          0x4e
#define RMI_INPUTSTREAM_MESSAGE_NOTSUPPORTED 0x4f
#define RMI_INPUTSTREAM_MESSAGE_RETURNDATA   0x51
#define RMI_INPUTSTREAM_MESSAGE_PINGACK      0x53

typedef enum {
    CONTINUATION        = 1,
    RMI_OUTPUTSTREAM    = 2,
    RMI_OUTPUTMESSAGE   = 3,
    RMI_INPUTSTREAM     = 16,
    SERIALIZATION_DATA  = 128
} rmi_type;

#endif
