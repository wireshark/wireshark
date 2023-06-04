/* export_sslkeys.c
 *
 * Export SSL Session Keys dialog
 * by Sake Blok <sake@euronet.nl> (20110526)
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <glib.h>

#include <epan/address.h>
#include <epan/dissectors/packet-tls-utils.h>

#include "ui/ssl_key_export.h"

int
ssl_session_key_count(void)
{
    ssl_master_key_map_t *mk_map = tls_get_master_key_map(FALSE);
    if (!mk_map)
        return 0;

    return g_hash_table_size(mk_map->used_session) +
           g_hash_table_size(mk_map->used_crandom);
}

static void
ssl_export_sessions_func(gpointer key, gpointer value, gpointer user_data)
{
    guint i;
    StringInfo *sslid = (StringInfo *)key;
    StringInfo *master_secret = (StringInfo *)value;
    GString *keylist = (GString *)user_data;

    g_string_append(keylist, "RSA Session-ID:");

    for (i = 0; i < sslid->data_len; i++) {
        g_string_append_printf(keylist, "%.2x", sslid->data[i]);
    }

    g_string_append(keylist, " Master-Key:");

    for (i = 0; i < master_secret->data_len; i++) {
        g_string_append_printf(keylist, "%.2x", master_secret->data[i]);
    }

    g_string_append_c(keylist, '\n');
}

static void
tls_export_client_randoms_func(gpointer key, gpointer value, gpointer user_data, const char* label)
{
    guint i;
    StringInfo *client_random = (StringInfo *)key;
    StringInfo *master_secret = (StringInfo *)value;
    GString *keylist = (GString *)user_data;

    g_string_append(keylist, label);

    for (i = 0; i < client_random->data_len; i++) {
        g_string_append_printf(keylist, "%.2x", client_random->data[i]);
    }

    g_string_append_c(keylist, ' ');

    for (i = 0; i < master_secret->data_len; i++) {
        g_string_append_printf(keylist, "%.2x", master_secret->data[i]);
    }

    g_string_append_c(keylist, '\n');
}

gchar*
ssl_export_sessions(gsize *length)
{
    /* Output format is:
     * "RSA Session-ID:xxxx Master-Key:yyyy\n"
     * Where xxxx is the session ID in hex (max 64 chars)
     * Where yyyy is the Master Key in hex (always 96 chars)
     * So in total max 3+1+11+64+1+11+96+2 = 189 chars
     * or
     * "CLIENT_RANDOM zzzz yyyy\n"
     * Where zzzz is the client random (always 64 chars)
     * Where yyyy is same as above
     * So length will always be 13+1+64+1+96+2 = 177 chars
     *
     * Wireshark can read CLIENT_RANDOM since v1.8.0.
     * Both values are exported in case you use the Session-ID for resuming a
     * session in a different capture.
     *
     * TLS 1.3 derived secrets are similar to the CLIENT_RANDOM master secret
     * export, but with a (longer) label indicating the type of derived secret
     * to which the client random maps, e.g.
     * "CLIENT_HANDSHAKE_TRAFFIC_SECRET zzzz yyyy\n"
     *
     * The TLS 1.3 values are obtained from an existing key log, but exporting
     * them is useful in order to filter actually used secrets.
     * (Eventually, this can be used to add a DSB as well, issue #18400)
     */
    ssl_master_key_map_t *mk_map = tls_get_master_key_map(FALSE);

    if (!mk_map) {
        *length = 0;
        return g_strdup("");
    }

    /* This at least provides a minimum for the string length. */
    gsize len = 189 * g_hash_table_size(mk_map->used_session) +
                177 * g_hash_table_size(mk_map->used_crandom);
    GString *keylist = g_string_sized_new(len);

    GHashTableIter iter;
    gpointer key, value;

    g_hash_table_iter_init(&iter, mk_map->used_session);
    while (g_hash_table_iter_next(&iter, &key, NULL)) {
        if ((value = g_hash_table_lookup(mk_map->session, key))) {
            ssl_export_sessions_func(key, value, (gpointer)keylist);
        }
    }

    g_hash_table_iter_init(&iter, mk_map->used_crandom);
    while (g_hash_table_iter_next(&iter, &key, NULL)) {
        if ((value = g_hash_table_lookup(mk_map->crandom, key))) {
            tls_export_client_randoms_func(key, value, (gpointer)keylist, "CLIENT_RANDOM ");
        }
        if ((value = g_hash_table_lookup(mk_map->tls13_client_early, key))) {
            tls_export_client_randoms_func(key, value, (gpointer)keylist, "CLIENT_EARLY_TRAFFIC_SECRET ");
        }
        if ((value = g_hash_table_lookup(mk_map->tls13_client_handshake, key))) {
            tls_export_client_randoms_func(key, value, (gpointer)keylist, "CLIENT_HANDSHAKE_TRAFFIC_SECRET ");
        }
        if ((value = g_hash_table_lookup(mk_map->tls13_server_handshake, key))) {
            tls_export_client_randoms_func(key, value, (gpointer)keylist, "SERVER_HANDSHAKE_TRAFFIC_SECRET ");
        }
        if ((value = g_hash_table_lookup(mk_map->tls13_server_appdata, key))) {
            tls_export_client_randoms_func(key, value, (gpointer)keylist, "SERVER_TRAFFIC_SECRET_0 ");
        }
        if ((value = g_hash_table_lookup(mk_map->tls13_client_appdata, key))) {
            tls_export_client_randoms_func(key, value, (gpointer)keylist, "CLIENT_TRAFFIC_SECRET_0 ");
        }
        if ((value = g_hash_table_lookup(mk_map->tls13_early_exporter, key))) {
            tls_export_client_randoms_func(key, value, (gpointer)keylist, "EARLY_EXPORTER_SECRET ");
        }
        if ((value = g_hash_table_lookup(mk_map->tls13_exporter, key))) {
            tls_export_client_randoms_func(key, value, (gpointer)keylist, "EXPORTER_SECRET ");
        }
    }

    *length = keylist->len;
    return g_string_free(keylist, FALSE);
}
