/* packet-iwarp-ddp-rdmap.c
 * Routines for Direct Data Placement (DDP) and
 * Remote Direct Memory Access Protocol (RDMAP) dissection
 * According to IETF RFC 5041 and RFC 5040
 * Copyright 2008, Yves Geissbuehler <yves.geissbuehler@gmx.net>
 * Copyright 2008, Philip Frey <frey.philip@gmail.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#ifndef __PACKET_IWARP_DDP_RDMAP_H_
#define __PACKET_IWARP_DDP_RDMAP_H_

/* RDMA messages */
#define RDMA_WRITE 0x00
#define RDMA_READ_REQUEST 0x01
#define RDMA_READ_RESPONSE 0x02
#define RDMA_SEND 0x03
#define RDMA_SEND_INVALIDATE 0x04
#define RDMA_SEND_SE 0x05
#define RDMA_SEND_SE_INVALIDATE 0x06
#define RDMA_TERMINATE 0x07

/* Read request info */
typedef struct rdmap_request {
	uint32_t sink_stag;
	uint64_t sink_toffset;
	uint32_t source_stag;
	uint64_t source_toffset;
	uint32_t message_size;
} rdmap_request_t;

typedef struct rdmapinfo {
	uint8_t  opcode;
	bool last_flag;
	bool is_tagged;
	union {
		/* Tagged Buffer Model */
		struct {
			uint32_t steering_tag;
			uint64_t tagged_offset;
		};
		/* Untagged Buffer Model */
		struct {
			uint32_t queue_number;
			uint32_t message_seq_num;
			uint32_t message_offset;
		};
	};
	rdmap_request_t *read_request;
} rdmap_info_t;

#endif /* __PACKET_IWARP_DDP_RDMAP_H_ */
