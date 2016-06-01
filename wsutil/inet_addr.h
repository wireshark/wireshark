/* inet_addr.h
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

#ifndef __WS_INET_ADDR_H__
#define __WS_INET_ADDR_H__

#include "ws_symbol_export.h"

#include <glib.h>

#include "inet_ipv6.h"

#define WS_INET6_ADDRSTRLEN     46


WS_DLL_PUBLIC const gchar *
ws_inet_ntop4(gconstpointer src, gchar *dst, guint dst_size);

WS_DLL_PUBLIC gboolean
ws_inet_pton4(const gchar *src, guint32 *dst);

WS_DLL_PUBLIC const gchar *
ws_inet_ntop6(gconstpointer src, gchar *dst, guint dst_size);

WS_DLL_PUBLIC gboolean
ws_inet_pton6(const gchar *src, struct e_in6_addr *dst);

#endif
