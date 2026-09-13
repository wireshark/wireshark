/* process_lookup.c
 * Look up the processes that have a network socket open
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"
#define WS_LOG_DOMAIN LOG_DOMAIN_WSUTIL

#include "process_lookup.h"
#include "process_lookup_int.h"

#include <string.h>

#define DEFAULT_REFRESH_INTERVAL_MS 250

/* A process in the cache. */
typedef struct {
    ws_process_info_t info;
    unsigned          verified_seq;  /* the refresh at which it was last confirmed to be the same process */
} process_entry_t;

struct ws_process_lookup {
    void       *backend_state;
    GHashTable *sockets;             /* ws_process_lookup_socket_key_t * -> GArray of the pids that have it open */
    GHashTable *processes;           /* pid -> process_entry_t * */
    GPtrArray  *retired;             /* entries replaced when their PID was reused; kept for callers holding them */
    unsigned    refresh_interval_ms;
    int64_t     last_refresh;        /* monotonic time of the last refresh, in microseconds; 0 = never */
    unsigned    refresh_seq;
};

static unsigned
socket_key_hash(const void *key)
{
    const uint8_t *p = (const uint8_t *)key;
    unsigned h = 2166136261u;  /* FNV-1a */

    for (size_t i = 0; i < sizeof(ws_process_lookup_socket_key_t); i++) {
        h ^= p[i];
        h *= 16777619u;
    }
    return h;
}

static gboolean
socket_key_equal(const void *a, const void *b)
{
    return memcmp(a, b, sizeof(ws_process_lookup_socket_key_t)) == 0;
}

static bool
addr_is_zero(const uint8_t *addr, size_t len)
{
    for (size_t i = 0; i < len; i++) {
        if (addr[i] != 0)
            return false;
    }
    return true;
}

static bool
addr_is_v4_mapped(const uint8_t *addr6)
{
    static const uint8_t prefix[12] = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff };

    return memcmp(addr6, prefix, sizeof prefix) == 0;
}

void
ws_process_lookup_key_init(ws_process_lookup_socket_key_t *key,
                           uint8_t protocol, uint8_t ip_version,
                           const uint8_t *local_addr, uint16_t local_port,
                           const uint8_t *remote_addr, uint16_t remote_port)
{
    size_t addr_len;

    memset(key, 0, sizeof *key);
    key->protocol = protocol;

    /* An IPv4 socket seen through an IPv6 socket is an IPv4 socket. */
    if (ip_version == 6 && addr_is_v4_mapped(local_addr)) {
        ip_version = 4;
        local_addr += 12;
        if (remote_addr != NULL)
            remote_addr += 12;
    }
    addr_len = (ip_version == 6) ? 16 : 4;

    if (remote_addr != NULL &&
        (remote_port != 0 || !addr_is_zero(remote_addr, addr_len))) {
        memcpy(key->remote_addr, remote_addr, addr_len);
        key->remote_port = remote_port;
    }
    if (addr_is_zero(local_addr, addr_len)) {
        /* Bound to any address; matches either IP version. */
        key->ip_version = 0;
    } else {
        key->ip_version = ip_version;
        memcpy(key->local_addr, local_addr, addr_len);
    }
    key->local_port = local_port;
}

static void
pid_array_free(void *p)
{
    g_array_free((GArray *)p, TRUE);
}

static void
set_err_msg(char **err_msg, const char *msg)
{
    if (err_msg != NULL)
        *err_msg = g_strdup(msg);
}

bool
ws_process_lookup_supported(void)
{
    return ws_process_lookup_backend.supported;
}

ws_process_lookup_t *
ws_process_lookup_new(char **err_msg)
{
    ws_process_lookup_t *lookup;
    void *state;
    char *backend_err = NULL;

    if (!ws_process_lookup_backend.supported) {
        set_err_msg(err_msg, "Looking up the processes that own sockets is not supported on this platform");
        return NULL;
    }
    state = ws_process_lookup_backend.create(&backend_err);
    if (state == NULL) {
        if (err_msg != NULL)
            *err_msg = backend_err;
        else
            g_free(backend_err);
        return NULL;
    }

    lookup = g_new0(ws_process_lookup_t, 1);
    lookup->backend_state = state;
    lookup->sockets = g_hash_table_new_full(socket_key_hash, socket_key_equal, g_free, pid_array_free);
    lookup->processes = g_hash_table_new(g_direct_hash, g_direct_equal);
    lookup->retired = g_ptr_array_new();
    lookup->refresh_interval_ms = DEFAULT_REFRESH_INTERVAL_MS;
    return lookup;
}

static void
process_info_clear(ws_process_info_t *info)
{
    g_free(info->name);
    g_free(info->path);
    g_free(info->user);
    g_free(info->cmdline);
    memset(info, 0, sizeof *info);
}

static void
process_entry_free(void *p)
{
    process_entry_t *entry = (process_entry_t *)p;

    process_info_clear(&entry->info);
    g_free(entry);
}

static void
process_entry_free_value(void *key _U_, void *value, void *user_data _U_)
{
    process_entry_free(value);
}

void
ws_process_lookup_free(ws_process_lookup_t *lookup)
{
    if (lookup == NULL)
        return;
    g_hash_table_destroy(lookup->sockets);
    g_hash_table_foreach(lookup->processes, process_entry_free_value, NULL);
    g_hash_table_destroy(lookup->processes);
    for (unsigned i = 0; i < lookup->retired->len; i++)
        process_entry_free(g_ptr_array_index(lookup->retired, i));
    g_ptr_array_free(lookup->retired, TRUE);
    ws_process_lookup_backend.destroy(lookup->backend_state);
    g_free(lookup);
}

void
ws_process_lookup_set_refresh_interval(ws_process_lookup_t *lookup, unsigned interval_ms)
{
    lookup->refresh_interval_ms = interval_ms;
}

static void
add_socket(void *ctx, const ws_process_lookup_socket_key_t *key, uint32_t pid)
{
    ws_process_lookup_t *lookup = (ws_process_lookup_t *)ctx;
    GArray *pids = (GArray *)g_hash_table_lookup(lookup->sockets, key);

    if (pids == NULL) {
        pids = g_array_new(FALSE, FALSE, sizeof(uint32_t));
        g_hash_table_insert(lookup->sockets, g_memdup2(key, sizeof *key), pids);
    }
    for (unsigned i = 0; i < pids->len; i++) {
        if (g_array_index(pids, uint32_t, i) == pid)
            return;  /* the same process, through another descriptor */
    }
    g_array_append_val(pids, pid);
}

bool
ws_process_lookup_refresh(ws_process_lookup_t *lookup, char **err_msg)
{
    char *backend_err = NULL;

    g_hash_table_remove_all(lookup->sockets);
    lookup->refresh_seq++;
    lookup->last_refresh = g_get_monotonic_time();
    if (!ws_process_lookup_backend.refresh(lookup->backend_state, add_socket,
                                           lookup, &backend_err)) {
        ws_debug("refreshing the socket tables failed: %s", backend_err);
        if (err_msg != NULL)
            *err_msg = backend_err;
        else
            g_free(backend_err);
        return false;
    }
    ws_noisy("refreshed the socket tables: %u sockets with owners",
             g_hash_table_size(lookup->sockets));
    return true;
}

/*
 * Find the processes that have a socket open in the snapshot: an exact
 * match, else a socket bound to the local end alone, else one bound to
 * the local port on any address. NULL if there is none.
 */
static const GArray *
find_socket(ws_process_lookup_t *lookup, const ws_process_lookup_socket_key_t *key)
{
    ws_process_lookup_socket_key_t k;
    const GArray *pids;

    pids = (const GArray *)g_hash_table_lookup(lookup->sockets, key);
    if (pids != NULL)
        return pids;

    k = *key;
    if (k.remote_port != 0 || !addr_is_zero(k.remote_addr, sizeof k.remote_addr)) {
        memset(k.remote_addr, 0, sizeof k.remote_addr);
        k.remote_port = 0;
        pids = (const GArray *)g_hash_table_lookup(lookup->sockets, &k);
        if (pids != NULL)
            return pids;
    }
    if (k.ip_version != 0) {
        k.ip_version = 0;
        memset(k.local_addr, 0, sizeof k.local_addr);
        pids = (const GArray *)g_hash_table_lookup(lookup->sockets, &k);
        if (pids != NULL)
            return pids;
    }
    return NULL;
}

/*
 * Get the record of a process, describing it if it is not yet cached or
 * has not been checked since the last refresh, when its ID may have been
 * reused by a new process. known_to_exist says the socket tables named it,
 * in which case at least its ID is returned even if it cannot be described.
 */
static ws_process_info_t *
get_process(ws_process_lookup_t *lookup, uint32_t pid, bool known_to_exist)
{
    process_entry_t *entry;
    ws_process_info_t fresh;

    entry = (process_entry_t *)g_hash_table_lookup(lookup->processes, GUINT_TO_POINTER(pid));
    if (entry != NULL && entry->verified_seq == lookup->refresh_seq)
        return &entry->info;

    memset(&fresh, 0, sizeof fresh);
    fresh.pid = pid;
    if (!ws_process_lookup_backend.describe(lookup->backend_state, pid, &fresh)) {
        /* No such process, at least not any more. */
        if (entry != NULL) {
            /* What we know about it is still the best description. */
            entry->verified_seq = lookup->refresh_seq;
            return &entry->info;
        }
        if (!known_to_exist)
            return NULL;
        /* It had a socket a moment ago; report its ID at least. */
    }
    if (entry != NULL) {
        if (entry->info.start_time_ns == fresh.start_time_ns) {
            /* The same process, or no way to tell; keep the cached record. */
            process_info_clear(&fresh);
            entry->verified_seq = lookup->refresh_seq;
            return &entry->info;
        }
        /* The ID was reused; keep the old record alive for whoever holds it. */
        g_ptr_array_add(lookup->retired, entry);
    }
    entry = g_new0(process_entry_t, 1);
    entry->info = fresh;
    entry->verified_seq = lookup->refresh_seq;
    g_hash_table_insert(lookup->processes, GUINT_TO_POINTER(pid), entry);
    return &entry->info;
}

static const uint8_t *
endpoint_addr(const ws_socket_endpoint_t *ep)
{
    return (ep->ip_version == 6) ? ep->addr.ipv6.bytes : (const uint8_t *)&ep->addr.ipv4;
}

/*
 * The order in which the processes that have a socket open are reported:
 * the one that has had it longest first, normally the one that created
 * it. A process whose start time is unknown comes last.
 */
static bool
process_before(const ws_process_info_t *a, const ws_process_info_t *b)
{
    if (a->start_time_ns != b->start_time_ns) {
        if (a->start_time_ns == 0 || b->start_time_ns == 0)
            return b->start_time_ns == 0;
        return a->start_time_ns < b->start_time_ns;
    }
    return a->pid < b->pid;
}

unsigned
ws_process_lookup_socket(ws_process_lookup_t *lookup,
                         ws_process_lookup_protocol_t protocol,
                         const ws_socket_endpoint_t *local,
                         const ws_socket_endpoint_t *remote,
                         GPtrArray *processes)
{
    ws_process_lookup_socket_key_t key;
    const GArray *pids;
    unsigned first, added = 0;

    if (lookup == NULL || local == NULL || processes == NULL ||
        (local->ip_version != 4 && local->ip_version != 6))
        return 0;
    if (remote != NULL && remote->ip_version != local->ip_version)
        remote = NULL;
    ws_process_lookup_key_init(&key, (uint8_t)protocol, local->ip_version,
                               endpoint_addr(local), local->port,
                               remote != NULL ? endpoint_addr(remote) : NULL,
                               remote != NULL ? remote->port : 0);

    if (lookup->last_refresh == 0) {
        if (!ws_process_lookup_refresh(lookup, NULL))
            return 0;
    }
    pids = find_socket(lookup, &key);
    if (pids == NULL &&
        g_get_monotonic_time() - lookup->last_refresh >= (int64_t)lookup->refresh_interval_ms * 1000) {
        /* Not in the snapshot; it may be a new socket. */
        if (!ws_process_lookup_refresh(lookup, NULL))
            return 0;
        pids = find_socket(lookup, &key);
    }
    if (pids == NULL)
        return 0;

    first = processes->len;
    for (unsigned i = 0; i < pids->len; i++) {
        ws_process_info_t *info = get_process(lookup, g_array_index(pids, uint32_t, i), true);
        unsigned pos;

        if (info == NULL)
            continue;
        /* Keep the processes added by this call in order; there are rarely more than one or two. */
        for (pos = first + added; pos > first; pos--) {
            if (!process_before(info, (const ws_process_info_t *)g_ptr_array_index(processes, pos - 1)))
                break;
        }
        g_ptr_array_insert(processes, (int)pos, info);
        added++;
    }
    return added;
}

const ws_process_info_t *
ws_process_lookup_pid(ws_process_lookup_t *lookup, uint32_t pid)
{
    if (lookup == NULL)
        return NULL;
    return get_process(lookup, pid, false);
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
