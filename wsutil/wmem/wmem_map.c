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

#ifdef HAVE_XXHASH
#include <xxhash.h>
#endif /* HAVE_XXHASH */

#include "wmem_core.h"
#include "wmem_list.h"
#include "wmem_map.h"
#include "wmem_map_int.h"
#include "wmem_user_cb.h"

#include "wsutil/ws_assert.h"
#include "wsutil/bits_ctz.h"

static uint32_t x; /* Used for universal integer hashing (see the HASH macro) */

/* Used for the wmem_strong_hash() function */
static uint32_t preseed;
static uint32_t postseed;

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

    /* Store the full hash to speed up collisions and resizing, avoiding
     * recalculating it or in some cases doing the equality function.
     * In the g_direct_hash case (especially if the equality function
     * is g_direct_equal), we don't need to store it, but it's probably
     * not worth implementing a parallel API for the direct map case.
     */
    uint32_t hash;
} wmem_map_item_t;

struct _wmem_map_t {
    /* Number of items stored. */
    size_t count;

    /* The base-2 logarithm of the actual size of the table. We store this
     * value for efficiency in hashing, since finding the actual capacity
     * becomes just a left-shift (see the CAPACITY macro) whereas taking
     * logarithms is expensive. Limited to 32 (GHashFunc returns an unsigned,
     * which might be 32 bits; also see how the HASH is shifted.) */
    unsigned capacity;
    unsigned min_capacity;

    wmem_map_item_t **table;
    wmem_map_item_t *items;

    /* Next unused item in the items array */
    wmem_map_item_t *next_item;

    /* An pointer array of items that had keys removed from the map without
     * replacing their values. For more speed, we could instead just leave such
     * items orphaned (not decrementing map->count but keeping a count of
     * deleted items so that wmem_map_size is accurate). The map would be more
     * likely to reach the item count limit (2^32) with many removals and
     * insertions (but our largest uses do not remove items so that might be
     * acceptable.)
     */
    GPtrArray *deleted_items;

    GHashFunc  hash_func;
    GEqualFunc eql_func;

    unsigned   metadata_scope_cb_id;
    unsigned   data_scope_cb_id;

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
    ((uint32_t)((MAP)->hash_func(KEY) * x))

#define MASK_HASH(MAP, HASH) ((uint32_t)((HASH) >> (32 - (MAP)->capacity)))

static void
wmem_map_init_table(wmem_map_t *map)
{
    map->count     = 0;
    map->capacity  = map->min_capacity;
    map->table     = wmem_alloc0_array(map->data_allocator, wmem_map_item_t*, CAPACITY(map));
    /* We do *not* need to 0 these, unlike the pointers. */
    map->items     = wmem_alloc_array(map->data_allocator, wmem_map_item_t, CAPACITY(map));
    map->next_item = map->items;
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
    map->min_capacity = WMEM_MAP_DEFAULT_CAPACITY;
    map->table = NULL;
    map->items = NULL;
    map->next_item = NULL;
    map->deleted_items = g_ptr_array_new();

    return map;
}

static bool
wmem_map_reset_cb(wmem_allocator_t *allocator _U_, wmem_cb_event_t event,
        void *user_data)
{
    wmem_map_t *map = (wmem_map_t*)user_data;

    map->count = 0;
    map->table = NULL;
    map->items = NULL;
    map->next_item = NULL;
    g_ptr_array_set_size(map->deleted_items, 0);

    if (event == WMEM_CB_DESTROY_EVENT) {
        wmem_unregister_callback(map->metadata_allocator, map->metadata_scope_cb_id);
        wmem_free(map->metadata_allocator, map);
    }

    return true;
}

static bool
wmem_map_destroy_cb(wmem_allocator_t *allocator _U_, wmem_cb_event_t event _U_,
        void *user_data)
{
    wmem_map_t *map = (wmem_map_t*)user_data;

    wmem_unregister_callback(map->data_allocator, map->data_scope_cb_id);

    return false;
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
    map->min_capacity = WMEM_MAP_DEFAULT_CAPACITY;
    map->table = NULL;
    map->items = NULL;
    map->next_item = NULL;
    map->deleted_items = g_ptr_array_new();

    map->metadata_scope_cb_id = wmem_register_callback(metadata_scope, wmem_map_destroy_cb, map);
    map->data_scope_cb_id  = wmem_register_callback(data_scope, wmem_map_reset_cb, map);

    return map;
}

static inline void
wmem_map_grow(wmem_map_t *map, unsigned new_capacity)
{
    wmem_map_item_t **old_table, *cur, *nxt;
    size_t            old_cap, i;
    unsigned          slot;

    if (new_capacity > 32) {
        // Run time error
        // XXX - If we really need to support more than 2^32 items,
        // we can allocate a new items array without changing
        // the number of slots in this case.
        ws_error("wmem_map does not support more than 2^32 items");
        return;
    }

    if (new_capacity < map->capacity) {
        ws_info("wmem_map does not support shrinking");
        return;
    }

    /* store the old table and capacity */
    old_table = map->table;
    old_cap   = CAPACITY(map);

    /* double the size (capacity is base-2 logarithm, so this just means
     * increment it) and allocate new table */
    map->capacity = new_capacity;
    map->table = wmem_alloc0_array(map->data_allocator, wmem_map_item_t*, CAPACITY(map));
    /* allocate new items, continuing to use the existing items. */
    /* XXX - If this is called when the map is not full (i.e., when
     * map->count != old_cap, which can only happen if calling
     * wmem_map_reserve after inserting items), then some items are
     * orphaned. Alternatively we could do a more expensive copy in that
     * case.  */
    map->items = wmem_alloc_array(map->data_allocator, wmem_map_item_t, CAPACITY(map) - map->count);
    map->next_item = map->items;

    /* copy all the elements over from the old table */
    for (i=0; i<old_cap; i++) {
        cur = old_table[i];
        while (cur) {
            nxt              = cur->next;
            slot             = MASK_HASH(map, cur->hash);
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
    uint32_t hash = HASH(map, key);
    item = &(map->table[MASK_HASH(map, hash)]);

    /* check existing items in that slot */
    while (*item) {
        if ((hash == (*item)->hash) && map->eql_func(key, (*item)->key)) {
            /* replace and return old value for this key */
            old_val = (*item)->value;
            (*item)->value = value;
            return old_val;
        }
        item = &((*item)->next);
    }

    /* insert new item */
    if (map->deleted_items->len) {
        *item = g_ptr_array_remove_index_fast(map->deleted_items, map->deleted_items->len - 1);
    } else {
        ws_assert(map->next_item);
        *item = map->next_item++;
    }

    (*item)->key   = key;
    (*item)->value = value;
    (*item)->next  = NULL;
    (*item)->hash  = hash;

    map->count++;

    /* increase size if we are over-full */
    if (map->count >= CAPACITY(map)) {
        wmem_map_grow(map, map->capacity + 1);
    }

    /* no previous entry, return NULL */
    return NULL;
}

bool
wmem_map_contains(wmem_map_t *map, const void *key)
{
    wmem_map_item_t *item;

    /* Make sure we have map and a table */
    if (map == NULL || map->table == NULL) {
        return false;
    }

    /* find correct slot */
    uint32_t hash = HASH(map, key);
    item = map->table[MASK_HASH(map, hash)];

    /* scan list of items in this slot for the correct value */
    while (item) {
        if ((hash == item->hash) && map->eql_func(key, item->key)) {
            return true;
        }
        item = item->next;
    }

    return false;
}

void *
wmem_map_lookup(wmem_map_t *map, const void *key)
{
    wmem_map_item_t *item;

    /* Make sure we have map and a table */
    if (map == NULL || map->table == NULL) {
        return NULL;
    }

    /* find correct slot */
    uint32_t hash = HASH(map, key);
    item = map->table[MASK_HASH(map, hash)];

    /* scan list of items in this slot for the correct value */
    while (item) {
        if ((hash == item->hash) && map->eql_func(key, item->key)) {
            return item->value;
        }
        item = item->next;
    }

    return NULL;
}

bool
wmem_map_lookup_extended(wmem_map_t *map, const void *key, const void **orig_key, void **value)
{
    wmem_map_item_t *item;

    /* Make sure we have map and a table */
    if (map == NULL || map->table == NULL) {
        return false;
    }

    /* find correct slot */
    uint32_t hash = HASH(map, key);
    item = map->table[MASK_HASH(map, hash)];

    /* scan list of items in this slot for the correct value */
    while (item) {
        if ((hash == item->hash) && map->eql_func(key, item->key)) {
            if (orig_key) {
                *orig_key = item->key;
            }
            if (value) {
                *value = item->value;
            }
            return true;
        }
        item = item->next;
    }

    return false;
}

void *
wmem_map_remove(wmem_map_t *map, const void *key)
{
    wmem_map_item_t **item, *tmp;
    void *value;

    /* Make sure we have map and a table */
    if (map == NULL || map->table == NULL) {
        return NULL;
    }

    /* get a pointer to the slot */
    uint32_t hash = HASH(map, key);
    item = &(map->table[MASK_HASH(map, hash)]);

    /* check the items in that slot */
    while (*item) {
        if ((hash == (*item)->hash) && map->eql_func(key, (*item)->key)) {
            /* found it */
            tmp     = (*item);
            value   = tmp->value;
            (*item) = tmp->next;
            g_ptr_array_add(map->deleted_items, tmp);
            map->count--;
            return value;
        }
        item = &((*item)->next);
    }

    /* didn't find it */
    return NULL;
}

bool
wmem_map_steal(wmem_map_t *map, const void *key)
{
    wmem_map_item_t **item, *tmp;

    /* Make sure we have map and a table */
    if (map == NULL || map->table == NULL) {
        return false;
    }

    /* get a pointer to the slot */
    uint32_t hash = HASH(map, key);
    item = &(map->table[MASK_HASH(map, hash)]);

    /* check the items in that slot */
    while (*item) {
        if ((hash == (*item)->hash) && map->eql_func(key, (*item)->key)) {
            /* found it */
            tmp     = (*item);
            (*item) = tmp->next;
            g_ptr_array_add(map->deleted_items, tmp);
            map->count--;
            return true;
        }
        item = &((*item)->next);
    }

    /* didn't find it */
    return false;
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
wmem_map_foreach(wmem_map_t *map, GHFunc foreach_func, void * user_data)
{
    wmem_map_item_t *cur;
    unsigned i;

    /* Make sure we have a table */
    if (map == NULL || map->table == NULL) {
        return;
    }

    for (i = 0; i < CAPACITY(map); i++) {
        cur = map->table[i];
        while (cur) {
            foreach_func((void *)cur->key, (void *)cur->value, user_data);
            cur = cur->next;
        }
    }
}

void*
wmem_map_find(wmem_map_t *map, GHRFunc foreach_func, void * user_data)
{
    wmem_map_item_t **item;
    unsigned i;

    /* Make sure we have a table */
    if (map == NULL || map->table == NULL) {
        return 0;
    }

    for (i = 0; i < CAPACITY(map); i++) {
        item = &(map->table[i]);
        while (*item) {
            if (foreach_func((void *)(*item)->key, (void *)(*item)->value, user_data)) {
                return (*item)->value;
            } else {
                item = &((*item)->next);
            }
        }
    }
    return NULL;
}

unsigned
wmem_map_foreach_remove(wmem_map_t *map, GHRFunc foreach_func, void * user_data)
{
    wmem_map_item_t **item, *tmp;
    unsigned i, deleted = 0;

    /* Make sure we have a table */
    if (map == NULL || map->table == NULL) {
        return 0;
    }

    for (i = 0; i < CAPACITY(map); i++) {
        item = &(map->table[i]);
        while (*item) {
            if (foreach_func((void *)(*item)->key, (void *)(*item)->value, user_data)) {
                tmp   = *item;
                *item = tmp->next;
                g_ptr_array_add(map->deleted_items, tmp);
                map->count--;
                deleted++;
            } else {
                item = &((*item)->next);
            }
        }
    }
    return deleted;
}

unsigned
wmem_map_size(wmem_map_t *map)
{
    return (unsigned)map->count;
}

size_t
wmem_map_reserve(wmem_map_t *map, uint64_t capacity)
{
    ws_return_val_if(!capacity, CAPACITY(map));

    map->min_capacity = ws_ilog2(capacity) + 1;

    map->min_capacity = MAX(map->min_capacity, WMEM_MAP_DEFAULT_CAPACITY);

    if (map->table) {
        /* XXX - Should reserving after an item has been inserted be allowed?
         * Either we orphan some items in the old array or have to do a more
         * expensive copy operation.
         */
        ws_warning("Capacity should be reserved when first creating a map.");
        wmem_map_grow(map, map->min_capacity);
    }

    map->min_capacity = MIN(map->min_capacity, 32);

    return CAPACITY(map);
}

/* Borrowed from Perl 5.18. This is based on Bob Jenkin's one-at-a-time
 * algorithm with some additional randomness seeded in. It is believed to be
 * generally secure against collision attacks. See
 * http://blog.booking.com/hardening-perls-hash-function.html
 */
uint32_t
wmem_strong_hash(const uint8_t *buf, const size_t len)
{
#ifdef HAVE_XXHASH
    return (uint32_t)XXH3_64bits_withSeed(buf, len, postseed);
#else
    const uint8_t * const end = (const uint8_t *)buf + len;
    uint32_t hash = preseed + (uint32_t)len;

    while (buf < end) {
        hash += (hash << 10);
        hash ^= (hash >> 6);
        hash += *buf++;
    }

    hash += (hash << 10);
    hash ^= (hash >> 6);
    hash += ((uint8_t*)&postseed)[0];

    hash += (hash << 10);
    hash ^= (hash >> 6);
    hash += ((uint8_t*)&postseed)[1];

    hash += (hash << 10);
    hash ^= (hash >> 6);
    hash += ((uint8_t*)&postseed)[2];

    hash += (hash << 10);
    hash ^= (hash >> 6);
    hash += ((uint8_t*)&postseed)[3];

    hash += (hash << 10);
    hash ^= (hash >> 6);

    hash += (hash << 3);
    hash ^= (hash >> 11);
    return (hash + (hash << 15));
#endif /* HAVE_XXHASH */
}

unsigned
wmem_str_hash(const void *key)
{
#ifdef HAVE_XXHASH
    return (uint32_t)XXH3_64bits_withSeed((const uint8_t*)key, strlen((const char*)key), postseed);
#else
    return g_str_hash(key);
#endif
}

/* No need for a strong hash here, for our purpose fast functions are more important */
unsigned
wmem_int64_hash(const void *key)
{
    return g_int64_hash(key);
}

unsigned
wmem_double_hash(const void *key)
{
    return g_double_hash(key);
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
