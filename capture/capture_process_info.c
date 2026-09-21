/* capture_process_info.c
 * Attribute captured packets to the processes that sent or received them
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"
#define WS_LOG_DOMAIN LOG_DOMAIN_CAPTURE

#include "capture_process_info.h"
#include "capture_ifinfo.h"

#include <string.h>

#include <wsutil/packet_endpoints.h>

/* How often this host's addresses are listed again, in case they change. */
#define LOCAL_ADDRS_REFRESH_INTERVAL_US (30 * G_USEC_PER_SEC)

struct capture_process_info {
    ws_process_lookup_t *lookup;
    capture_process_info_iface_list_func get_iface_list;
    GHashTable *local_addrs;       /* GBytes: IP version, then the address -> present */
    int64_t     local_addrs_time;  /* monotonic time they were last listed */
    GHashTable *described;         /* const ws_process_info_t * described in the current file */
    GPtrArray  *other_end;         /* scratch: the processes at the other end of a loopback packet */
};

static void
bytes_unref(void *p)
{
    g_bytes_unref((GBytes *)p);
}

static GBytes *
addr_key(uint8_t ip_version, const uint8_t *addr)
{
    uint8_t key[17];
    size_t addr_len = (ip_version == 6) ? 16 : 4;

    key[0] = ip_version;
    memcpy(key + 1, addr, addr_len);
    return g_bytes_new(key, 1 + addr_len);
}

/* List this host's addresses; on failure the last list is kept. */
static void
refresh_local_addrs(capture_process_info_t *cpi)
{
    int err = 0;
    char *err_str = NULL;
    GList *if_list;

    cpi->local_addrs_time = g_get_monotonic_time();
    if_list = cpi->get_iface_list(&err, &err_str);
    if (if_list == NULL && err != 0) {
        ws_warning("Can't list this host's addresses, to tell which end of a packet is local: %s",
                   err_str != NULL ? err_str : "unknown error");
        g_free(err_str);
        return;
    }
    g_hash_table_remove_all(cpi->local_addrs);
    for (GList *entry = if_list; entry != NULL; entry = entry->next) {
        const if_info_t *if_info = (const if_info_t *)entry->data;

        for (GSList *addr_entry = if_info->addrs; addr_entry != NULL; addr_entry = addr_entry->next) {
            const if_addr_t *addr = (const if_addr_t *)addr_entry->data;

            if (addr->ifat_type == IF_AT_IPv4)
                g_hash_table_add(cpi->local_addrs, addr_key(4, (const uint8_t *)&addr->addr.ip4_addr));
            else if (addr->ifat_type == IF_AT_IPv6)
                g_hash_table_add(cpi->local_addrs, addr_key(6, addr->addr.ip6_addr));
        }
    }
    free_interface_list(if_list);
    ws_debug("this host has %u addresses", g_hash_table_size(cpi->local_addrs));
}

/*
 * Whether an end of a packet is on this host: a loopback address, one of
 * the host's addresses or, for the destination, a broadcast or multicast
 * address that a socket on this host would receive.
 */
static bool
endpoint_is_local(capture_process_info_t *cpi, const ws_socket_endpoint_t *ep, bool is_destination)
{
    static const uint8_t loopback6[16] = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 };
    const uint8_t *addr;
    GBytes *key;
    bool local;

    if (ep->ip_version == 4) {
        addr = (const uint8_t *)&ep->addr.ipv4;
        if (addr[0] == 127)
            return true;
        if (is_destination &&
            ((addr[0] >= 224 && addr[0] <= 239) ||
             (addr[0] == 255 && addr[1] == 255 && addr[2] == 255 && addr[3] == 255)))
            return true;
    } else {
        addr = ep->addr.ipv6.bytes;
        if (memcmp(addr, loopback6, sizeof loopback6) == 0)
            return true;
        if (is_destination && addr[0] == 0xff)
            return true;
    }
    key = addr_key(ep->ip_version, addr);
    local = g_hash_table_contains(cpi->local_addrs, key);
    g_bytes_unref(key);
    return local;
}

capture_process_info_t *
capture_process_info_new(capture_process_info_iface_list_func get_iface_list,
                         ws_process_detail_t detail, char **err_msg)
{
    capture_process_info_t *cpi;
    ws_process_lookup_t *lookup;

    lookup = ws_process_lookup_new(err_msg);
    if (lookup == NULL)
        return NULL;
    ws_process_lookup_set_detail(lookup, detail);
    cpi = g_new0(capture_process_info_t, 1);
    cpi->lookup = lookup;
    cpi->get_iface_list = get_iface_list;
    cpi->local_addrs = g_hash_table_new_full(g_bytes_hash, g_bytes_equal, bytes_unref, NULL);
    cpi->described = g_hash_table_new(g_direct_hash, g_direct_equal);
    cpi->other_end = g_ptr_array_new();
    refresh_local_addrs(cpi);
    return cpi;
}

void
capture_process_info_free(capture_process_info_t *cpi)
{
    if (cpi == NULL)
        return;
    g_ptr_array_free(cpi->other_end, TRUE);
    g_hash_table_destroy(cpi->described);
    g_hash_table_destroy(cpi->local_addrs);
    ws_process_lookup_free(cpi->lookup);
    g_free(cpi);
}

bool
capture_process_info_linktype_supported(int linktype)
{
    return ws_packet_endpoints_linktype_supported(linktype);
}

unsigned
capture_process_info_lookup(capture_process_info_t *cpi, int linktype,
                            const uint8_t *data, size_t len, GPtrArray *processes)
{
    ws_packet_endpoints_t ep;
    unsigned first = processes->len;
    unsigned added = 0;

    if (!ws_packet_endpoints_parse(linktype, data, len, &ep))
        return 0;
    if (g_get_monotonic_time() - cpi->local_addrs_time >= LOCAL_ADDRS_REFRESH_INTERVAL_US)
        refresh_local_addrs(cpi);

    if (endpoint_is_local(cpi, &ep.src, false))
        added += ws_process_lookup_socket(cpi->lookup, ep.protocol, &ep.src, &ep.dst, processes);
    if (endpoint_is_local(cpi, &ep.dst, true)) {
        /* The receiving end is on this host too, e.g. over loopback. */
        g_ptr_array_set_size(cpi->other_end, 0);
        ws_process_lookup_socket(cpi->lookup, ep.protocol, &ep.dst, &ep.src, cpi->other_end);
        for (unsigned i = 0; i < cpi->other_end->len; i++) {
            void *process = g_ptr_array_index(cpi->other_end, i);
            bool known = false;

            for (unsigned j = first; j < processes->len && !known; j++)
                known = (g_ptr_array_index(processes, j) == process);
            if (!known) {
                g_ptr_array_add(processes, process);
                added++;
            }
        }
    }
    return added;
}

void
capture_process_info_new_file(capture_process_info_t *cpi)
{
    g_hash_table_remove_all(cpi->described);
}

bool
capture_process_info_needs_description(capture_process_info_t *cpi, const ws_process_info_t *process)
{
    /* The records are kept, unchanged, until the context is freed, so they identify processes. */
    return g_hash_table_add(cpi->described, (void *)process);
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
