/* wmem_map.c
 * Wireshark Memory Manager Hash Map
 * Copyright 2014, Evan Huus <eapache@gmail.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#include "config.h"

#include <glib.h>

#include "wmem_core.h"
#include "wmem_list.h"
#include "wmem_map.h"
#include "wmem_map_int.h"
#include "wmem_user_cb.h"

static guint32 x; /* Used for universal integer hashing (see the HASH macro) */

/* Used for the wmem_strong_hash() function */
static guint32 preseed;
static guint32 postseed;

void
wmem_init_hashing(void)
{
    x = g_random_int();
    if (G_UNLIKELY(x == 0))
        x = 1;

    preseed  = g_random_int();
    postseed = g_random_int();
}

typedef struct _wmem_map_item_t {
    const void *key;
    void *value;
    struct _wmem_map_item_t *next;
} wmem_map_item_t;

struct _wmem_map_t {
    guint count; /* number of items stored */

    /* The base-2 logarithm of the actual size of the table. We store this
     * value for efficiency in hashing, since finding the actual capacity
     * becomes just a left-shift (see the CAPACITY macro) whereas taking
     * logarithms is expensive. */
    size_t capacity;

    wmem_map_item_t **table;

    GHashFunc  hash_func;
    GEqualFunc eql_func;

    guint      metadata_scope_cb_id;
    guint      data_scope_cb_id;

    wmem_allocator_t *metadata_allocator;
    wmem_allocator_t *data_allocator;
};

/* As per the comment on the 'capacity' member of the wmem_map_t struct, this is
 * the base-2 logarithm, meaning the actual default capacity is 2^5 = 32 */
#define WMEM_MAP_DEFAULT_CAPACITY 5

/* Macro for calculating the real capacity of the map by using a left-shift to
 * do the 2^x operation. */
#define CAPACITY(MAP) (((size_t)1) << (MAP)->capacity)

/* Efficient universal integer hashing:
 * https://en.wikipedia.org/wiki/Universal_hashing#Avoiding_modular_arithmetic
 */
#define HASH(MAP, KEY) \
    ((guint32)(((MAP)->hash_func(KEY) * x) >> (32 - (MAP)->capacity)))

static void
wmem_map_init_table(wmem_map_t *map)
{
    map->count     = 0;
    map->capacity  = WMEM_MAP_DEFAULT_CAPACITY;
    map->table     = wmem_alloc0_array(map->data_allocator, wmem_map_item_t*, CAPACITY(map));
}

wmem_map_t *
wmem_map_new(wmem_allocator_t *allocator,
        GHashFunc hash_func, GEqualFunc eql_func)
{
    wmem_map_t *map;

    map = wmem_new(allocator, wmem_map_t);

    map->hash_func = hash_func;
    map->eql_func  = eql_func;
    map->metadata_allocator    = allocator;
    map->data_allocator = allocator;
    map->count = 0;
    map->table = NULL;

    return map;
}

static gboolean
wmem_map_reset_cb(wmem_allocator_t *allocator _U_, wmem_cb_event_t event,
        void *user_data)
{
    wmem_map_t *map = (wmem_map_t*)user_data;

    map->count = 0;
    map->table = NULL;

    if (event == WMEM_CB_DESTROY_EVENT) {
        wmem_unregister_callback(map->metadata_allocator, map->metadata_scope_cb_id);
        wmem_free(map->metadata_allocator, map);
    }

    return TRUE;
}

static gboolean
wmem_map_destroy_cb(wmem_allocator_t *allocator _U_, wmem_cb_event_t event _U_,
        void *user_data)
{
    wmem_map_t *map = (wmem_map_t*)user_data;

    wmem_unregister_callback(map->data_allocator, map->data_scope_cb_id);

    return FALSE;
}

wmem_map_t *
wmem_map_new_autoreset(wmem_allocator_t *metadata_scope, wmem_allocator_t *data_scope,
        GHashFunc hash_func, GEqualFunc eql_func)
{
    wmem_map_t *map;

    map = wmem_new(metadata_scope, wmem_map_t);

    map->hash_func = hash_func;
    map->eql_func  = eql_func;
    map->metadata_allocator = metadata_scope;
    map->data_allocator = data_scope;
    map->count = 0;
    map->table = NULL;

    map->metadata_scope_cb_id = wmem_register_callback(metadata_scope, wmem_map_destroy_cb, map);
    map->data_scope_cb_id  = wmem_register_callback(data_scope, wmem_map_reset_cb, map);

    return map;
}

static inline void
wmem_map_grow(wmem_map_t *map)
{
    wmem_map_item_t **old_table, *cur, *nxt;
    size_t            old_cap, i;
    guint             slot;

    /* store the old table and capacity */
    old_table = map->table;
    old_cap   = CAPACITY(map);

    /* double the size (capacity is base-2 logarithm, so this just means
     * increment it) and allocate new table */
    map->capacity++;
    map->table = wmem_alloc0_array(map->data_allocator, wmem_map_item_t*, CAPACITY(map));

    /* copy all the elements over from the old table */
    for (i=0; i<old_cap; i++) {
        cur = old_table[i];
        while (cur) {
            nxt              = cur->next;
            slot             = HASH(map, cur->key);
            cur->next        = map->table[slot];
            map->table[slot] = cur;
            cur              = nxt;
        }
    }

    /* free the old table */
    wmem_free(map->data_allocator, old_table);
}

void *
wmem_map_insert(wmem_map_t *map, const void *key, void *value)
{
    wmem_map_item_t **item;
    void *old_val;

    /* Make sure we have a table */
    if (map->table == NULL) {
        wmem_map_init_table(map);
    }

    /* get a pointer to the slot */
    item = &(map->table[HASH(map, key)]);

    /* check existing items in that slot */
    while (*item) {
        if (map->eql_func(key, (*item)->key)) {
            /* replace and return old value for this key */
            old_val = (*item)->value;
            (*item)->value = value;
            return old_val;
        }
        item = &((*item)->next);
    }

    /* insert new item */
    (*item) = wmem_new(map->data_allocator, wmem_map_item_t);

    (*item)->key   = key;
    (*item)->value = value;
    (*item)->next  = NULL;

    map->count++;

    /* increase size if we are over-full */
    if (map->count >= CAPACITY(map)) {
        wmem_map_grow(map);
    }

    /* no previous entry, return NULL */
    return NULL;
}

gboolean
wmem_map_contains(wmem_map_t *map, const void *key)
{
    wmem_map_item_t *item;

    /* Make sure we have a table */
    if (map->table == NULL) {
        return FALSE;
    }

    /* find correct slot */
    item = map->table[HASH(map, key)];

    /* scan list of items in this slot for the correct value */
    while (item) {
        if (map->eql_func(key, item->key)) {
            return TRUE;
        }
        item = item->next;
    }

    return FALSE;
}

void *
wmem_map_lookup(wmem_map_t *map, const void *key)
{
    wmem_map_item_t *item;

    /* Make sure we have a table */
    if (map->table == NULL) {
        return NULL;
    }

    /* find correct slot */
    item = map->table[HASH(map, key)];

    /* scan list of items in this slot for the correct value */
    while (item) {
        if (map->eql_func(key, item->key)) {
            return item->value;
        }
        item = item->next;
    }

    return NULL;
}

gboolean
wmem_map_lookup_extended(wmem_map_t *map, const void *key, const void **orig_key, void **value)
{
    wmem_map_item_t *item;

    /* Make sure we have a table */
    if (map->table == NULL) {
        return FALSE;
    }

    /* find correct slot */
    item = map->table[HASH(map, key)];

    /* scan list of items in this slot for the correct value */
    while (item) {
        if (map->eql_func(key, item->key)) {
            if (orig_key) {
                *orig_key = item->key;
            }
            if (value) {
                *value = item->value;
            }
            return TRUE;
        }
        item = item->next;
    }

    return FALSE;
}

void *
wmem_map_remove(wmem_map_t *map, const void *key)
{
    wmem_map_item_t **item, *tmp;
    void *value;

    /* Make sure we have a table */
    if (map->table == NULL) {
        return NULL;
    }

    /* get a pointer to the slot */
    item = &(map->table[HASH(map, key)]);

    /* check the items in that slot */
    while (*item) {
        if (map->eql_func(key, (*item)->key)) {
            /* found it */
            tmp     = (*item);
            value   = tmp->value;
            (*item) = tmp->next;
            wmem_free(map->data_allocator, tmp);
            map->count--;
            return value;
        }
        item = &((*item)->next);
    }

    /* didn't find it */
    return NULL;
}

gboolean
wmem_map_steal(wmem_map_t *map, const void *key)
{
    wmem_map_item_t **item, *tmp;

    /* Make sure we have a table */
    if (map->table == NULL) {
        return FALSE;
    }

    /* get a pointer to the slot */
    item = &(map->table[HASH(map, key)]);

    /* check the items in that slot */
    while (*item) {
        if (map->eql_func(key, (*item)->key)) {
            /* found it */
            tmp     = (*item);
            (*item) = tmp->next;
            map->count--;
            return TRUE;
        }
        item = &((*item)->next);
    }

    /* didn't find it */
    return FALSE;
}

wmem_list_t*
wmem_map_get_keys(wmem_allocator_t *list_allocator, wmem_map_t *map)
{
    size_t capacity, i;
    wmem_map_item_t *cur;
    wmem_list_t* list = wmem_list_new(list_allocator);

    if (map->table != NULL) {
        capacity = CAPACITY(map);

        /* copy all the elements into the list over from table */
        for (i=0; i<capacity; i++) {
            cur = map->table[i];
            while (cur) {
                wmem_list_prepend(list, (void*)cur->key);
                cur = cur->next;
            }
        }
    }

    return list;
}

void
wmem_map_foreach(wmem_map_t *map, GHFunc foreach_func, gpointer user_data)
{
    wmem_map_item_t *cur;
    unsigned i;

    /* Make sure we have a table */
    if (map->table == NULL) {
        return;
    }

    for (i = 0; i < CAPACITY(map); i++) {
        cur = map->table[i];
        while (cur) {
            foreach_func((gpointer)cur->key, (gpointer)cur->value, user_data);
            cur = cur->next;
        }
    }
}

guint
wmem_map_size(wmem_map_t *map)
{
    return map->count;
}

/* Borrowed from Perl 5.18. This is based on Bob Jenkin's one-at-a-time
 * algorithm with some additional randomness seeded in. It is believed to be
 * generally secure against collision attacks. See
 * http://blog.booking.com/hardening-perls-hash-function.html
 */
guint32
wmem_strong_hash(const guint8 *buf, const size_t len)
{
    const guint8 * const end = (const guint8 *)buf + len;
    guint32 hash = preseed + (guint32)len;

    while (buf < end) {
        hash += (hash << 10);
        hash ^= (hash >> 6);
        hash += *buf++;
    }

    hash += (hash << 10);
    hash ^= (hash >> 6);
    hash += ((guint8*)&postseed)[0];

    hash += (hash << 10);
    hash ^= (hash >> 6);
    hash += ((guint8*)&postseed)[1];

    hash += (hash << 10);
    hash ^= (hash >> 6);
    hash += ((guint8*)&postseed)[2];

    hash += (hash << 10);
    hash ^= (hash >> 6);
    hash += ((guint8*)&postseed)[3];

    hash += (hash << 10);
    hash ^= (hash >> 6);

    hash += (hash << 3);
    hash ^= (hash >> 11);
    return (hash + (hash << 15));
}

guint
wmem_str_hash(gconstpointer key)
{
    return wmem_strong_hash((const guint8 *)key, strlen((const char *)key));
}

guint
wmem_int64_hash(gconstpointer key)
{
    return wmem_strong_hash((const guint8 *)key, sizeof(guint64));
}

guint
wmem_double_hash(gconstpointer key)
{
    return wmem_strong_hash((const guint8 *)key, sizeof(double));
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
