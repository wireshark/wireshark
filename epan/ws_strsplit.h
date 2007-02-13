/* ws_strsplit.h
 * String Split utility function
 * Code borrowed from GTK2 to override the GTK1 version of g_strsplit, which is
 * known to be buggy.
 *
 * $Id$
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */

#ifndef __WS_STRSPLIT_H__
#define __WS_STRSPLIT_H__

#if GLIB_MAJOR_VERSION < 2

#define g_strsplit(s, d, t) ws_strsplit(s, d, t)

gchar ** ws_strsplit (const gchar *string,
		      const gchar *delimiter,
		      gint max_tokens);

#endif /* GLIB_MAJOR_VERSION */

#endif /* __WS_STRSPLIT_H__ */

