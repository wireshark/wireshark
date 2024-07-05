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

#include <wiretap/secrets-types.h>

#include "ui/ssl_key_export.h"

int
ssl_session_key_count(void)
{
    int count = 0;
    ssl_master_key_map_t *mk_map = tls_get_master_key_map(false);
    if (!mk_map || !mk_map->used_crandom)
        return count;

    GHashTableIter iter;
    void *key;

    g_hash_table_iter_init(&iter, mk_map->used_crandom);
    while (g_hash_table_iter_next(&iter, &key, NULL)) {
        if (g_hash_table_contains(mk_map->crandom, key)) {
            count++;
        }
        if (g_hash_table_contains(mk_map->tls13_client_early, key)) {
            count++;
        }
        if (g_hash_table_contains(mk_map->tls13_client_handshake, key)) {
            count++;
        }
        if (g_hash_table_contains(mk_map->tls13_server_handshake, key)) {
            count++;
        }
        if (g_hash_table_contains(mk_map->tls13_client_appdata, key)) {
            count++;
        }
        if (g_hash_table_contains(mk_map->tls13_server_appdata, key)) {
            count++;
        }
    }
    return count;
}

static void
tls_export_client_randoms_func(void *key, void *value, void *user_data, const char* label)
{
    unsigned i;
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

char*
ssl_export_sessions(size_t *length)
{
    /* Output format is:
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
     * them is useful in order to filter actually used secrets or add a DSB.
     */
    ssl_master_key_map_t *mk_map = tls_get_master_key_map(false);

    if (!mk_map) {
        *length = 0;
        return g_strdup("");
    }

    size_t len = 177 * (size_t)ssl_session_key_count();
    GString *keylist = g_string_sized_new(len);

    GHashTableIter iter;
    void *key, *value;

    g_hash_table_iter_init(&iter, mk_map->used_crandom);
    while (g_hash_table_iter_next(&iter, &key, NULL)) {
        if ((value = g_hash_table_lookup(mk_map->crandom, key))) {
            tls_export_client_randoms_func(key, value, (void *)keylist, "CLIENT_RANDOM ");
        }
        if ((value = g_hash_table_lookup(mk_map->tls13_client_early, key))) {
            tls_export_client_randoms_func(key, value, (void *)keylist, "CLIENT_EARLY_TRAFFIC_SECRET ");
        }
        if ((value = g_hash_table_lookup(mk_map->tls13_client_handshake, key))) {
            tls_export_client_randoms_func(key, value, (void *)keylist, "CLIENT_HANDSHAKE_TRAFFIC_SECRET ");
        }
        if ((value = g_hash_table_lookup(mk_map->tls13_server_handshake, key))) {
            tls_export_client_randoms_func(key, value, (void *)keylist, "SERVER_HANDSHAKE_TRAFFIC_SECRET ");
        }
        if ((value = g_hash_table_lookup(mk_map->tls13_server_appdata, key))) {
            tls_export_client_randoms_func(key, value, (void *)keylist, "SERVER_TRAFFIC_SECRET_0 ");
        }
        if ((value = g_hash_table_lookup(mk_map->tls13_client_appdata, key))) {
            tls_export_client_randoms_func(key, value, (void *)keylist, "CLIENT_TRAFFIC_SECRET_0 ");
        }
#if 0
        /* We don't use the EARLY_EXPORT_SECRET or EXPORTER_SECRET now so don't
           export, but we may in the future. */
        if ((value = g_hash_table_lookup(mk_map->tls13_early_exporter, key))) {
            tls_export_client_randoms_func(key, value, (void *)keylist, "EARLY_EXPORTER_SECRET ");
        }
        if ((value = g_hash_table_lookup(mk_map->tls13_exporter, key))) {
            tls_export_client_randoms_func(key, value, (void *)keylist, "EXPORTER_SECRET ");
        }
#endif
    }

    *length = keylist->len;
    return g_string_free(keylist, FALSE);
}

void
tls_export_dsb(capture_file *cf)
{
    wtap_block_t block;
    wtapng_dsb_mandatory_t *dsb;
    size_t secrets_len;
    char* secrets = ssl_export_sessions(&secrets_len);

    block = wtap_block_create(WTAP_BLOCK_DECRYPTION_SECRETS);
    dsb = (wtapng_dsb_mandatory_t *)wtap_block_get_mandatory_data(block);

    dsb->secrets_type = SECRETS_TYPE_TLS;
    dsb->secrets_data = g_memdup2(secrets, secrets_len);
    dsb->secrets_len = (unsigned)secrets_len;

    /* XXX - support replacing the DSB of the same type instead of adding? */
    wtap_file_add_decryption_secrets(cf->provider.wth, block);
    /* Mark the file as having unsaved changes */
    cf->unsaved_changes = true;

    return;
}
