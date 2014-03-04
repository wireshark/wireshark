/* garrayfix.h
 * Macros to work around the "data" field of a GArray having type guint8 *,
 * rather than void *, so that, even though the GArray code should be
 * ensuring that the data is aligned strictly enough for any data type,
 * we still get warnings with -Wcast-align.
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 2007 Gerald Combs
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

#ifndef __GARRAYFIX_H__
#define __GARRAYFIX_H__

#ifdef g_array_index
#undef g_array_index
#define g_array_index(a,t,i)      (((t*) (void*) (a)->data) [(i)])
#endif

#define g_array_data(a)	((void*) (a)->data)

#endif /* __GARRAYFIX_H__ */
