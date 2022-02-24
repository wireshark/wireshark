/** @file
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __INET_IPV4_H__
#define __INET_IPV4_H__

#include <glib.h>

typedef guint32 ws_in4_addr;	/* 32 bit IPv4 address, in network byte order */

/*
 * We define these in *network byte order*, unlike the C library. Therefore
 * it uses a different prefix than INADDR_* to make the distinction more obvious.
 */
#define WS_IN4_LOOPBACK ((ws_in4_addr)GUINT32_TO_BE(0x7f000001))

/**
 * Unicast Local
 * Returns true if the address is in the 224.0.0.0/24 local network
 * control block
 */
#define in4_addr_is_local_network_control_block(addr) \
  ((addr & 0xffffff00) == 0xe0000000)

/**
 * Multicast
 * Returns true if the address is in the 224.0.0.0/4 network block
 */
#define in4_addr_is_multicast(addr) \
  ((addr & 0xf0000000) == 0xe0000000)

/**
 * Private address
 * Returns true if the address is in one of the three blocks reserved
 * for private IPv4 addresses by section 3 of RFC 1918, namely:
 * 10/8, 172.16/12, and 192.168/16
 */
#define in4_addr_is_private(addr) \
  (((addr & 0xff000000) == 0x0a000000) || \
   ((addr & 0xfff00000) == 0xac100000) || \
   ((addr & 0xffff0000) == 0xc0a80000))

/**
 * Link-local address
 * Returns true if the address is in the 169.254/16 network block
 */
#define in4_addr_is_link_local(addr) \
  ((addr & 0xffff0000) == 0xa9fe0000)

#endif
