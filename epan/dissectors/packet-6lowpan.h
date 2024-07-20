/* packet-6lowpan.h
 * Routines for 6LoWPAN packet disassembly
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __PACKET_6LOWPAN_H__
#define __PACKET_6LOWPAN_H__

#include <wsutil/inet_addr.h>

/* Inserts new compression context information into the 6LoWPAN context table.
 * The compression context is distributed via some options added to the neighbor
 * discovery protocol, so the ICMPv6 dissector needs to call this routine.
 */
extern void lowpan_context_insert(uint8_t cid, uint16_t pan, uint8_t plen,
                        ws_in6_addr *prefix, unsigned frame);

#endif /* __PACKET_6LOWPAN_H__ */
