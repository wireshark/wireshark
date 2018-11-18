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

#include "secrets.h"
#include <wiretap/wtap.h>

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
