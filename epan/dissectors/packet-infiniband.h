/* packet-infiniband.h
 * Routines for Infiniband/ERF Dissection
 * Copyright 2008 Endace Technology Limited
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * Modified 2010 by Mellanox Technologies Ltd.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#ifndef __PACKET_INFINIBAND_H_
#define __PACKET_INFINIBAND_H_

#define MAD_DATA_SIZE     232     /* size of data field a MAD payload carries */
#define GID_SIZE          16      /* size of GID = 128bit (same as IPv6) */

/* infiniband-specific information for conversations */
typedef struct {
    uint64_t service_id;         /* service id specified when the (RC) channel was set-up */
    bool client_to_server;  /* message direction */
    uint32_t src_qp;             /* originator src qp as this is not present in RC packets */

    /* store mad data so that it can be parsed for private data by ULP */
    uint8_t mad_private_data[MAD_DATA_SIZE];
} conversation_infiniband_data;

/* OpCodeValues
* Code Bits [7-5] Connection Type
*           [4-0] Message Type

* Reliable Connection (RC)
* [7-5] = 000 */
#define RC_SEND_FIRST                    0 /*0b00000000 */
#define RC_SEND_MIDDLE                   1 /*0b00000001 */
#define RC_SEND_LAST                     2 /*0b00000010 */
#define RC_SEND_LAST_IMM                 3 /*0b00000011 */
#define RC_SEND_ONLY                     4 /*0b00000100 */
#define RC_SEND_ONLY_IMM                 5 /*0b00000101 */
#define RC_RDMA_WRITE_FIRST              6 /*0b00000110 */
#define RC_RDMA_WRITE_MIDDLE             7 /*0b00000111 */
#define RC_RDMA_WRITE_LAST               8 /*0b00001000 */
#define RC_RDMA_WRITE_LAST_IMM           9 /*0b00001001 */
#define RC_RDMA_WRITE_ONLY              10 /*0b00001010 */
#define RC_RDMA_WRITE_ONLY_IMM          11 /*0b00001011 */
#define RC_RDMA_READ_REQUEST            12 /*0b00001100 */
#define RC_RDMA_READ_RESPONSE_FIRST     13 /*0b00001101 */
#define RC_RDMA_READ_RESPONSE_MIDDLE    14 /*0b00001110 */
#define RC_RDMA_READ_RESPONSE_LAST      15 /*0b00001111 */
#define RC_RDMA_READ_RESPONSE_ONLY      16 /*0b00010000 */
#define RC_ACKNOWLEDGE                  17 /*0b00010001 */
#define RC_ATOMIC_ACKNOWLEDGE           18 /*0b00010010 */
#define RC_CMP_SWAP                     19 /*0b00010011 */
#define RC_FETCH_ADD                    20 /*0b00010100 */
#define RC_SEND_LAST_INVAL              22 /*0b00010110 */
#define RC_SEND_ONLY_INVAL              23 /*0b00010111 */
#define RC_FLUSH                        28 /*0b00011100 */
#define RC_ATOMIC_WRITE                 29 /*0b00011101 */

/* Reliable Datagram (RD)
* [7-5] = 010 */
#define RD_SEND_FIRST                   64 /*0b01000000 */
#define RD_SEND_MIDDLE                  65 /*0b01000001 */
#define RD_SEND_LAST                    66 /*0b01000010 */
#define RD_SEND_LAST_IMM                67 /*0b01000011 */
#define RD_SEND_ONLY                    68 /*0b01000100 */
#define RD_SEND_ONLY_IMM                69 /*0b01000101 */
#define RD_RDMA_WRITE_FIRST             70 /*0b01000110 */
#define RD_RDMA_WRITE_MIDDLE            71 /*0b01000111 */
#define RD_RDMA_WRITE_LAST              72 /*0b01001000 */
#define RD_RDMA_WRITE_LAST_IMM          73 /*0b01001001 */
#define RD_RDMA_WRITE_ONLY              74 /*0b01001010 */
#define RD_RDMA_WRITE_ONLY_IMM          75 /*0b01001011 */
#define RD_RDMA_READ_REQUEST            76 /*0b01001100 */
#define RD_RDMA_READ_RESPONSE_FIRST     77 /*0b01001101 */
#define RD_RDMA_READ_RESPONSE_MIDDLE    78 /*0b01001110 */
#define RD_RDMA_READ_RESPONSE_LAST      79 /*0b01001111 */
#define RD_RDMA_READ_RESPONSE_ONLY      80 /*0b01010000 */
#define RD_ACKNOWLEDGE                  81 /*0b01010001 */
#define RD_ATOMIC_ACKNOWLEDGE           82 /*0b01010010 */
#define RD_CMP_SWAP                     83 /*0b01010011 */
#define RD_FETCH_ADD                    84 /*0b01010100 */
#define RD_RESYNC                       85 /*0b01010101 */
#define RD_FLUSH                        92 /*0b01011100 */
#define RD_ATOMIC_WRITE                 93 /*0b01011101 */

/* Unreliable Datagram (UD)
* [7-5] = 011 */
#define UD_SEND_ONLY                   100 /*0b01100100 */
#define UD_SEND_ONLY_IMM               101 /*0b01100101 */

/* Unreliable Connection (UC)
* [7-5] = 001 */
#define UC_SEND_FIRST                   32 /*0b00100000 */
#define UC_SEND_MIDDLE                  33 /*0b00100001 */
#define UC_SEND_LAST                    34 /*0b00100010 */
#define UC_SEND_LAST_IMM                35 /*0b00100011 */
#define UC_SEND_ONLY                    36 /*0b00100100 */
#define UC_SEND_ONLY_IMM                37 /*0b00100101 */
#define UC_RDMA_WRITE_FIRST             38 /*0b00100110 */
#define UC_RDMA_WRITE_MIDDLE            39 /*0b00100111 */
#define UC_RDMA_WRITE_LAST              40 /*0b00101000 */
#define UC_RDMA_WRITE_LAST_IMM          41 /*0b00101001 */
#define UC_RDMA_WRITE_ONLY              42 /*0b00101010 */
#define UC_RDMA_WRITE_ONLY_IMM          43 /*0b00101011 */

/* ComMgt class Attributes */
#define ATTR_CM_REQ             0x0010
#define ATTR_CM_REJ             0x0012
#define ATTR_CM_REP             0x0013
#define ATTR_CM_RTU             0x0014
#define ATTR_CM_DREQ            0x0015
#define ATTR_CM_DRSP            0x0016

/*
 * Private data passed from the infiniband dissector to payload subdissectors.
 */
struct infinibandinfo {
    proto_tree* payload_tree;
    uint8_t opCode;              /* OpCode from BTH header. */
    uint8_t pad_count;           /* PadCount from BTH header. */
    uint16_t cm_attribute_id;    /* attribute id for CM messages */
    uint32_t reth_remote_key;    /* Remote Key from RETH header */
    uint64_t reth_remote_address;/* Remote address from RETH header */
    uint32_t reth_dma_length;    /* DMA Length from RETH header */
    uint32_t packet_seq_num;     /* Packet sequence number */
    bool dctConnect;        /* indicator for DCT connect/disconnect */
};

#endif

/*
 * Editor modelines  -  https://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 4
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * vi: set shiftwidth=4 tabstop=8 expandtab:
 * :indentSize=4:tabSize=8:noTabs=true:
 */
