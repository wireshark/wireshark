/* addr_and_mask.h
 * Declarations of routines to fetch IPv4 and IPv6 addresses from a tvbuff
 * and then mask out bits other than those covered by a prefix length
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
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

#ifndef __ADDR_AND_MASK_H__
#define __ADDR_AND_MASK_H__

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
    guint8 *addr, guint32 prefix_len);

extern int tvb_get_ipv6_addr_with_prefix_len(tvbuff_t *tvb, int offset,
    struct e_in6_addr *addr, guint32 prefix_len);

guint32 ip_get_subnet_mask(const guint32 mask_length);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __ADDR_AND_MASK_H__  */
