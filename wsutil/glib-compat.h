/* glib-compat.h
* Definitions to provide some functions that are not present in older
* GLIB versions (down to 2.22)
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
#ifndef GLIB_COMPAT_H
#define GLIB_COMPAT_H

#include "ws_symbol_export.h"
#if !GLIB_CHECK_VERSION(2, 28, 0)
WS_DLL_PUBLIC void g_slist_free_full(GSList *list, GDestroyNotify  free_func);
WS_DLL_PUBLIC void g_list_free_full(GList *list, GDestroyNotify free_func);
WS_DLL_PUBLIC gint64 g_get_monotonic_time (void);
#endif

#endif /* GLIB_COMPAT_H */
