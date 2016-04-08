/* inet_ipv6.h
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

#ifndef __INET_IPV6_H__
#define __INET_IPV6_H__

struct e_in6_addr {
	guint8   bytes[16];		/**< 128 bit IP6 address */
};

/**
 * Unicast Scope
 * Note that we must check topmost 10 bits only, not 16 bits (see RFC2373).
 */
#if 0 /* XXX Currently unused */
static inline gboolean in6_is_addr_link_local(struct e_in6_addr *a) {
    if ((a->bytes[0] == 0xfe) && ((a->bytes[1] & 0xc0) == 0x80)) {
        return TRUE;
    }
    return FALSE;
}

static inline gboolean in6_is_addr_sitelocal(struct e_in6_addr *a) {
    if ((a->bytes[0] == 0xfe) && ((a->bytes[1] & 0xc0) == 0xc0)) {
        return TRUE;
    }
    return FALSE;
}
#endif

/**
 * Multicast
 */
static inline gboolean in6_is_addr_multicast(struct e_in6_addr *a) {
    if (a->bytes[0] == 0xff) {
        return TRUE;
    }
    return FALSE;
}

#endif
