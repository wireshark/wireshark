/* secrets.c
 * Secrets management and processing.
 * Copyright 2018, Peter Wu <peter@lekensteyn.nl>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include "secrets.h"
#include <wiretap/wtap.h>

#include <string.h>
#ifdef HAVE_LIBGNUTLS
#include <gnutls/gnutls.h>
#include <gnutls/abstract.h>
#endif  /* HAVE_LIBGNUTLS */

/** Maps guint32 secrets_type -> secrets_block_callback_t. */
static GHashTable *secrets_callbacks;

void
secrets_init(void)
{
    secrets_callbacks = g_hash_table_new(g_direct_hash, g_direct_equal);
}

void
secrets_cleanup(void)
{
    g_hash_table_destroy(secrets_callbacks);
    secrets_callbacks = NULL;
}

void
secrets_register_type(guint32 secrets_type, secrets_block_callback_t cb)
{
    g_hash_table_insert(secrets_callbacks, GUINT_TO_POINTER(secrets_type), (gpointer)cb);
}

void
secrets_wtap_callback(guint32 secrets_type, const void *secrets, guint size)
{
    secrets_block_callback_t cb = (secrets_block_callback_t)g_hash_table_lookup(
            secrets_callbacks, GUINT_TO_POINTER(secrets_type));
    if (cb) {
        cb(secrets, size);
    }
}

#ifdef HAVE_LIBGNUTLS
static guint
key_id_hash(gconstpointer key)
{
    const cert_key_id_t *key_id = (const cert_key_id_t *)key;
    const guint32 *dw = (const guint32 *)key_id->key_id;

    /* The public key' SHA-1 hash (which maps to a private key) has a uniform
     * distribution, hence simply xor'ing them should be sufficient. */
    return dw[0] ^ dw[1] ^ dw[2] ^ dw[3] ^ dw[4];
}

static gboolean
key_id_equal(gconstpointer a, gconstpointer b)
{
    const cert_key_id_t *key_id_a = (const cert_key_id_t *)a;
    const cert_key_id_t *key_id_b = (const cert_key_id_t *)b;

    return !memcmp(key_id_a, key_id_b, sizeof(*key_id_a));
}

GHashTable *
privkey_hash_table_new(void)
{
    return g_hash_table_new_full(key_id_hash, key_id_equal, g_free, (GDestroyNotify)gnutls_privkey_deinit);
}
#endif  /* HAVE_LIBGNUTLS */

/*
 * Editor modelines  -  https://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 4
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * vi: set shiftwidth=4 tabstop=8 expandtab:
 * :indentSize=4:tabSize=8:noTabs=true:
 */
