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
#ifndef __PACKET_INFINIBAND_H_
#define __PACKET_INFINIBAND_H_

#define MAD_DATA_SIZE     232     /* size of data field a MAD payload carries */
#define GID_SIZE          16      /* size of GID = 128bit (same as IPv6) */

/* infiniband-specific information for conversations */
typedef struct {
    guint64 service_id;         /* service id specified when the (RC) channel was set-up */
} conversation_infiniband_data;

/* OpCodeValues
* Code Bits [7-5] Connection Type
*           [4-0] Message Type

* Reliable Connection (RC)
* [7-5] = 000 */
#define RC_SEND_FIRST                    0 /*0x00000000 */
#define RC_SEND_MIDDLE                   1 /*0x00000001 */
#define RC_SEND_LAST                     2 /*0x00000010 */
#define RC_SEND_LAST_IMM                 3 /*0x00000011 */
#define RC_SEND_ONLY                     4 /*0x00000100 */
#define RC_SEND_ONLY_IMM                 5 /*0x00000101 */
#define RC_RDMA_WRITE_FIRST              6 /*0x00000110 */
#define RC_RDMA_WRITE_MIDDLE             7 /*0x00000111 */
#define RC_RDMA_WRITE_LAST               8 /*0x00001000 */
#define RC_RDMA_WRITE_LAST_IMM           9 /*0x00001001 */
#define RC_RDMA_WRITE_ONLY              10 /*0x00001010 */
#define RC_RDMA_WRITE_ONLY_IMM          11 /*0x00001011 */
#define RC_RDMA_READ_REQUEST            12 /*0x00001100 */
#define RC_RDMA_READ_RESPONSE_FIRST     13 /*0x00001101 */
#define RC_RDMA_READ_RESPONSE_MIDDLE    14 /*0x00001110 */
#define RC_RDMA_READ_RESPONSE_LAST      15 /*0x00001111 */
#define RC_RDMA_READ_RESPONSE_ONLY      16 /*0x00010000 */
#define RC_ACKNOWLEDGE                  17 /*0x00010001 */
#define RC_ATOMIC_ACKNOWLEDGE           18 /*0x00010010 */
#define RC_CMP_SWAP                     19 /*0x00010011 */
#define RC_FETCH_ADD                    20 /*0x00010100 */
#define RC_SEND_LAST_INVAL              22 /*0x00010110 */
#define RC_SEND_ONLY_INVAL              23 /*0x00010111 */

/* Reliable Datagram (RD)
* [7-5] = 010 */
#define RD_SEND_FIRST                   64 /*0x01000000 */
#define RD_SEND_MIDDLE                  65 /*0x01000001 */
#define RD_SEND_LAST                    66 /*0x01000010 */
#define RD_SEND_LAST_IMM                67 /*0x01000011 */
#define RD_SEND_ONLY                    68 /*0x01000100 */
#define RD_SEND_ONLY_IMM                69 /*0x01000101 */
#define RD_RDMA_WRITE_FIRST             70 /*0x01000110 */
#define RD_RDMA_WRITE_MIDDLE            71 /*0x01000111 */
#define RD_RDMA_WRITE_LAST              72 /*0x01001000 */
#define RD_RDMA_WRITE_LAST_IMM          73 /*0x01001001 */
#define RD_RDMA_WRITE_ONLY              74 /*0x01001010 */
#define RD_RDMA_WRITE_ONLY_IMM          75 /*0x01001011 */
#define RD_RDMA_READ_REQUEST            76 /*0x01001100 */
#define RD_RDMA_READ_RESPONSE_FIRST     77 /*0x01001101 */
#define RD_RDMA_READ_RESPONSE_MIDDLE    78 /*0x01001110 */
#define RD_RDMA_READ_RESPONSE_LAST      79 /*0x01001111 */
#define RD_RDMA_READ_RESPONSE_ONLY      80 /*0x01010000 */
#define RD_ACKNOWLEDGE                  81 /*0x01010001 */
#define RD_ATOMIC_ACKNOWLEDGE           82 /*0x01010010 */
#define RD_CMP_SWAP                     83 /*0x01010011 */
#define RD_FETCH_ADD                    84 /*0x01010100 */
#define RD_RESYNC                       85 /*0x01010101 */

/* Unreliable Datagram (UD)
* [7-5] = 011 */
#define UD_SEND_ONLY                   100 /*0x01100100 */
#define UD_SEND_ONLY_IMM               101 /*0x01100101 */

/* Unreliable Connection (UC)
* [7-5] = 001 */
#define UC_SEND_FIRST                   32 /*0x00100000 */
#define UC_SEND_MIDDLE                  33 /*0x00100001 */
#define UC_SEND_LAST                    34 /*0x00100010 */
#define UC_SEND_LAST_IMM                35 /*0x00100011 */
#define UC_SEND_ONLY                    36 /*0x00100100 */
#define UC_SEND_ONLY_IMM                37 /*0x00100101 */
#define UC_RDMA_WRITE_FIRST             38 /*0x00100110 */
#define UC_RDMA_WRITE_MIDDLE            39 /*0x00100111 */
#define UC_RDMA_WRITE_LAST              40 /*0x00101000 */
#define UC_RDMA_WRITE_LAST_IMM          41 /*0x00101001 */
#define UC_RDMA_WRITE_ONLY              42 /*0x00101010 */
#define UC_RDMA_WRITE_ONLY_IMM          43 /*0x00101011 */

/*
 * Private data passed from the infiniband dissector to payload subdissectors.
 */
struct infinibandinfo {
    guint8 opCode;              /* OpCode from BTH header. */
};

#endif
