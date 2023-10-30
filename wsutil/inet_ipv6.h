/** @file
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __INET_IPV6_H__
#define __INET_IPV6_H__

#include <inttypes.h>
#include <stdbool.h>

typedef struct e_in6_addr {
    uint8_t bytes[16];           /* 128 bit IPv6 address */
} ws_in6_addr;

/**
 * Unicast Scope
 * Note that we must check topmost 10 bits only, not 16 bits (see RFC2373).
 */
static inline bool in6_addr_is_linklocal(const ws_in6_addr *a)
{
    return (a->bytes[0] == 0xfe) && ((a->bytes[1] & 0xc0) == 0x80);
}

static inline bool in6_addr_is_sitelocal(const ws_in6_addr *a)
{
    return (a->bytes[0] == 0xfe) && ((a->bytes[1] & 0xc0) == 0xc0);
}

/**
 * Multicast
 */
static inline bool in6_addr_is_multicast(const ws_in6_addr *a)
{
    return a->bytes[0] == 0xff;
}

static inline bool in6_addr_is_uniquelocal(const ws_in6_addr *a)
{
    return (a->bytes[0] & 0xfe) == 0xfc;
}

#endif
