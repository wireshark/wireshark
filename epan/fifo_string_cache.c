/* fifo_string_cache.c
 * A string cache, possibly with a bounded size, using FIFO order to control
 * the size.
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#include <stdio.h>
#include "fifo_string_cache.h"

void
fifo_string_cache_init(fifo_string_cache_t *fcache, unsigned max_entries, GDestroyNotify string_free_func)
{
    fcache->set = g_hash_table_new_full(g_str_hash, g_str_equal, string_free_func, NULL);
    fcache->head = NULL;
    fcache->tail = NULL;
    fcache->max_entries = max_entries;
}

void
fifo_string_cache_free(fifo_string_cache_t *fcache)
{
    if (fcache->set != NULL) {
        g_hash_table_destroy(fcache->set);
        fcache->set = NULL;
    }
    if (fcache->head != NULL) {
        g_slist_free(fcache->head);
        fcache->head = NULL;
        fcache->tail = NULL;
    }
}

bool
fifo_string_cache_contains(fifo_string_cache_t *fcache, const char *entry)
{
    return g_hash_table_contains(fcache->set, entry);
}

bool
fifo_string_cache_insert(fifo_string_cache_t *fcache, const char *entry)
{
    GSList *prev_head;
    GSList *new_start_of_tail;

    // In GLIB 2.40, g_hash_table_insert() returns a bool that gives us what we
    // need (did the entry exist already?). But, if we're not using that
    // version, we need to first check if the entry exists. So we just check
    // the hash all the time, regardless of GLIB version.
    bool exists;
    exists = g_hash_table_contains(fcache->set, entry);
    if (exists) {
        return true;
    }

    // Shall we remove one item?
    if (fcache->max_entries > 0) {
        if (g_hash_table_size(fcache->set) == fcache->max_entries) {
            g_hash_table_remove(fcache->set, fcache->head->data);
            prev_head = fcache->head;
            fcache->head = fcache->head->next;
            g_slist_free_1(prev_head);

            // If max_entries is 1, the head was also the tail. Reset the tail.
            if (fcache->tail == prev_head) {
                fcache->tail = NULL;
            }

            // Now the size of the hash table is max_entries
        }
    }

    g_hash_table_insert(fcache->set, (void *) entry, /*value=*/NULL);
    // Do we need to constrain the number of entries?
    if (fcache->max_entries > 0) {
        // Keep track of the new entry at the end of the queue
        new_start_of_tail = g_slist_append(fcache->tail, (void *) entry);
        // Set the new tail
        if (fcache->tail == NULL) {
            fcache->tail = new_start_of_tail;
            // This is the first entry, so head is NULL too. Set it.
            fcache->head = new_start_of_tail;
        } else {
            fcache->tail = new_start_of_tail->next;
        }
    }

    return false;
}
