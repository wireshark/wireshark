/* g_int64_hash_routines.h
 * Declaration of gint64 hash table routines absent from GLib < 2.22
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

#ifndef __G_INT64_HASH_ROUTINES_H__
#define __G_INT64_HASH_ROUTINES_H__

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

#include <glib.h>

#include "ws_symbol_export.h"

/* g_int64_hash, g_int64_equal are defined starting glib 2.22 - otherwise,
   we have to provide them ourselves */
#if !GLIB_CHECK_VERSION(2,22,0)
WS_DLL_PUBLIC guint
g_int64_hash (gconstpointer v);

WS_DLL_PUBLIC gboolean
g_int64_equal (gconstpointer v1,
               gconstpointer v2);
#endif /* !GLIB_CHECK_VERSION(2,22,0) */

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* g_int64_hash_routines.h */
