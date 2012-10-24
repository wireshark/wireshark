/* export_sslkeys.h
 *
 * $Id$
 *
 * SSL session key utilities. Copied from ui/gkt/export_sslkeys.c
 * by Sake Blok <sake@euronet.nl> (20110526)
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

#ifndef __SSL_KEY_EXPORT_H__
#define __SSL_KEY_EXPORT_H__

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/** Return the number of available SSL session keys.
 *
 * @return The number of available SSL session keys.
 */
extern int ssl_session_key_count();

/** Dump our SSL Session Keys to a string
 *
 * @return A string containing all the SSL Session Keys. Must be freed with
 * g_free().
 */
extern gchar* ssl_export_sessions();

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __SSL_KEY_EXPORT_H__ */

/*
 * Editor modelines
 *
 * Local Variables:
 * c-basic-offset: 4
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * ex: set shiftwidth=4 tabstop=8 expandtab:
 * :indentSize=4:tabSize=8:noTabs=true:
 */
