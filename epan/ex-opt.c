/*
 *  ex-opt.c
 *
 * Extension command line options
 *
 * (c) 2006, Luis E. Garcia Ontanon <luis@ontanon.org>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <glib.h>
#include "ex-opt.h"

static GHashTable* ex_opts;

bool ex_opt_add(const char* ws_optarg) {
    char** splitted;

    if (!ex_opts)
        ex_opts = g_hash_table_new(g_str_hash,g_str_equal);

    splitted = g_strsplit(ws_optarg,":",2);

    if (splitted[0] && splitted[1]) {
        GPtrArray* this_opts = (GPtrArray *)g_hash_table_lookup(ex_opts,splitted[0]);

        if (this_opts) {
            g_ptr_array_add(this_opts,splitted[1]);
            g_free(splitted[0]);
        } else {
            this_opts = g_ptr_array_new();
            g_ptr_array_add(this_opts,splitted[1]);
            g_hash_table_insert(ex_opts,splitted[0],this_opts);
        }

        g_free(splitted);

        return true;
    } else {
        g_strfreev(splitted);
        return false;
    }
}

int ex_opt_count(const char* key) {
    GPtrArray* this_opts;

    if (! ex_opts)
        return 0;

    this_opts = (GPtrArray *)g_hash_table_lookup(ex_opts,key);

    if (this_opts) {
        return this_opts->len;
    } else {
        return 0;
    }
}

const char* ex_opt_get_nth(const char* key, unsigned key_index) {
    GPtrArray* this_opts;

    if (! ex_opts)
        return 0;

    this_opts = (GPtrArray *)g_hash_table_lookup(ex_opts,key);

    if (this_opts) {
        if (this_opts->len > key_index) {
            return (const char *)g_ptr_array_index(this_opts,key_index);
        } else {
            /* XXX: assert? */
            return NULL;
        }
    } else {
        return NULL;
    }

}

extern const char* ex_opt_get_next(const char* key) {
    GPtrArray* this_opts;

    if (! ex_opts)
        return 0;

    this_opts = (GPtrArray *)g_hash_table_lookup(ex_opts,key);

    if (this_opts) {
        if (this_opts->len)
            return (const char *)g_ptr_array_remove_index(this_opts,0);
        else
            return NULL;
    } else {
        return NULL;
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
