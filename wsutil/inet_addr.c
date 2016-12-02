/* inet_addr.c
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

#include "config.h"

#include "inet_addr.h"

#include "inet_addr-int.h"

static inline gboolean
_inet_pton(int af, const gchar *src, gpointer dst)
{
    gint ret;

    ret = inet_pton(af, src, dst);
    g_assert(ret >= 0);
    return ret == 1;
}

const gchar *
ws_inet_ntop4(gconstpointer src, gchar *dst, guint dst_size)
{
    return inet_ntop(AF_INET, src, dst, dst_size);
}

gboolean
ws_inet_pton4(const gchar *src, guint32 *dst)
{
    return _inet_pton(AF_INET, src, dst);
}

const gchar *
ws_inet_ntop6(gconstpointer src, gchar *dst, guint dst_size)
{
    return inet_ntop(AF_INET6, src, dst, dst_size);
}

gboolean
ws_inet_pton6(const gchar *src, struct e_in6_addr *dst)
{
    return _inet_pton(AF_INET6, src, dst);
}
