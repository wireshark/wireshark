/* packet-udx.h
 * Routines for UDX dissection
 * Copyright 2026, Prabakaran Sivakumar <zkasuran@gmail.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __PACKET_UDX_H__
#define __PACKET_UDX_H__

#include "ws_symbol_export.h"

#include <epan/conversation.h>

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/* Bounds the SACK blocks carried per packet. A packet carrying data is
 * limited by data_offset to 255 bytes of them, but one carrying none leaves
 * that byte zero and lets the blocks run to the end of the datagram, where
 * libudx sends up to UDX_MAX_SACKS of them. */
#define UDX_MAX_SACK_BLOCKS 50

/*
 * Queued on the "udx" tap: one decoded UDX header, with the stream it belongs
 * to and the addresses and ports of the datagram that carried it.
 *
 * Sequence and acknowledgement numbers count packets rather than bytes, so
 * seq advances by one per packet whatever the payload size. Consumers that
 * want a byte offset have to accumulate payload_len themselves.
 */
typedef struct udx_info {
    uint32_t id;            /* the receiver's stream id, as carried on the wire */
    uint32_t seq;           /* per-packet sequence counter */
    uint32_t ack;           /* next seq expected from the peer */
    uint32_t window;        /* sender's receive window, in bytes */
    uint32_t payload_len;   /* payload bytes, excluding SACK blocks and padding */
    uint32_t stream;        /* Wireshark UDX stream index, as in udx.stream */
    uint32_t sport;         /* UDP source port of the carrying datagram */
    uint32_t dport;         /* UDP destination port of the carrying datagram */
    uint8_t  flags;         /* UDX type flags */
    uint8_t  data_offset;   /* bytes between the fixed header and the payload */
    address  ip_src;
    address  ip_dst;
    unsigned num_sack_blocks;
    uint32_t sack_start[UDX_MAX_SACK_BLOCKS];
    uint32_t sack_end[UDX_MAX_SACK_BLOCKS];
} udx_info_t;

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __PACKET_UDX_H__ */

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
