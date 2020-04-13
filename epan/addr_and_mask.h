/* addr_and_mask.h
 * Declarations of routines to fetch IPv4 and IPv6 addresses from a tvbuff
 * and then mask out bits other than those covered by a prefix length
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __ADDR_AND_MASK_H__
#define __ADDR_AND_MASK_H__

#include <wsutil/inet_ipv4.h>
#include <wsutil/inet_ipv6.h>

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/*
 * These routines return PREFIX_LEN_OK on success, PREFIX_LEN_TOO_LONG if
 * the prefix length is too long, and PREFIX_LEN_ZERO if the prefix length
 * is 0.
 */

#define PREFIX_LEN_OK		0
#define PREFIX_LEN_TOO_LONG	1
#define PREFIX_LEN_ZERO		2

extern int tvb_get_ipv4_addr_with_prefix_len(tvbuff_t *tvb, int offset,
    ws_in4_addr *addr, guint32 prefix_len);

extern int tvb_get_ipv6_addr_with_prefix_len(tvbuff_t *tvb, int offset,
    ws_in6_addr *addr, guint32 prefix_len);

guint32 ip_get_subnet_mask(const guint32 mask_length);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __ADDR_AND_MASK_H__  */
