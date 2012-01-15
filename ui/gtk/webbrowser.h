/* webbrowser.h
 * Web browser activation functions
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

#ifndef __WEBBROWSER_H__
#define __WEBBROWSER_H__

extern gboolean browser_needs_pref(void);

extern gboolean browser_open_url (const gchar *url);

extern gboolean filemanager_open_directory (const gchar *path);

/* browse a file relative to the data dir */
extern void browser_open_data_file (const gchar *filename);

/** Convert local absolute path to uri.
 *
 * @param filename to (absolute pathed) filename to convert
 * @return a newly allocated uri, you must g_free it later
 */
extern gchar *filename2uri(const gchar *filename);

#endif /* __WEBBROWSER_H__ */
