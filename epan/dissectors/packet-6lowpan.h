/* packet-6lowpan.h
 * Routines for 6LoWPAN packet disassembly
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __PACKET_6LOWPAN_H__
#define __PACKET_6LOWPAN_H__

/* Inserts new compression context information into the 6LoWPAN context table.
 * The compression context is distributed via some options added to the neighbor
 * discovery protocol, so the ICMPv6 dissector needs to call this routine.
 */
extern void lowpan_context_insert(guint8 cid, guint16 pan, guint8 plen,
                        ws_in6_addr *prefix, guint frame);

#endif /* __PACKET_6LOWPAN_H__ */
