/* export_sslkeys.c
 *
 * $Id$
 *
 * Export SSL Session Keys dialog
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

#include "config.h"

#include <glib.h>

#include <epan/address.h>
#include <epan/dissectors/packet-ssl.h>
#include <epan/dissectors/packet-ssl-utils.h>


int
ssl_session_key_count(void)
{
    return g_hash_table_size(ssl_session_hash);
}

static void
ssl_export_sessions_func(gpointer key, gpointer value, gpointer user_data)
{
    guint i;
    StringInfo* sslid = (StringInfo*)key;
    StringInfo* mastersecret = (StringInfo*)value;
    GString* keylist = (GString*)user_data;

    /*
     * XXX - should this be a string that grows as necessary to hold
     * everything in it?
     */
    g_string_append(keylist, "RSA Session-ID:");

    for( i=0; i<sslid->data_len; i++) {
        g_string_append_printf(keylist, "%.2x", sslid->data[i]&255);
    }

    g_string_append(keylist, " Master-Key:");

    for( i=0; i<mastersecret->data_len; i++) {
        g_string_append_printf(keylist, "%.2x", mastersecret->data[i]&255);
    }

    g_string_append_c(keylist, '\n');
}

gchar*
ssl_export_sessions(void)
{
    GString* keylist = g_string_new("");
    gchar *session_keys;

    /* Output format is:
     * "RSA Session-ID:xxxx Master-Key:yyyy\n"
     * Where xxxx is the session ID in hex (max 64 chars)
     * Where yyyy is the Master Key in hex (always 96 chars)
     * So in total max 3+1+11+64+1+11+96+2 = 189 chars
     */

    g_hash_table_foreach(ssl_session_hash, ssl_export_sessions_func, (gpointer)keylist);

    session_keys = keylist->str;
    g_string_free(keylist, FALSE);
    return session_keys;
}

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
