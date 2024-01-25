/* services.c
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "services.h"
#include <stdlib.h>

#include "services-data.c"


static int
compare_entry(const void *a, const void *b)
{
    return *(const uint16_t *)a - ((const ws_services_entry_t *)b)->port;
}

static inline
size_t global_tcp_udp_services_table_count(void)
{
    return G_N_ELEMENTS(global_tcp_udp_services_table);
}

static inline
size_t global_tcp_services_table_count(void)
{
    return G_N_ELEMENTS(global_tcp_services_table);
}

static inline
size_t global_udp_services_table_count(void)
{
    return G_N_ELEMENTS(global_udp_services_table);
}

static inline
size_t global_sctp_services_table_count(void)
{
    return G_N_ELEMENTS(global_sctp_services_table);
}

static inline
size_t global_dccp_services_table_count(void)
{
    return G_N_ELEMENTS(global_dccp_services_table);
}

ws_services_entry_t const *
global_services_lookup(uint16_t value, ws_services_proto_t proto)
{
    ws_services_entry_t const *list1 = NULL, *list2 = NULL;
    size_t list1_size, list2_size;
    ws_services_entry_t const *found;

    switch (proto) {
        case ws_tcp:
            list1 = global_tcp_udp_services_table;
            list1_size = global_tcp_udp_services_table_count();
            list2 = global_tcp_services_table;
            list2_size = global_tcp_services_table_count();
            break;
        case ws_udp:
            list1 = global_tcp_udp_services_table;
            list1_size = global_tcp_udp_services_table_count();
            list2 = global_udp_services_table;
            list2_size = global_udp_services_table_count();
            break;
        case ws_sctp:
            list1 = global_sctp_services_table;
            list1_size = global_sctp_services_table_count();
            break;
        case ws_dccp:
            list1 = global_dccp_services_table;
            list1_size = global_dccp_services_table_count();
            break;
        default:
            ws_assert_not_reached();
    }

    if (list1) {
        found = bsearch(&value, list1, list1_size, sizeof(ws_services_entry_t), compare_entry);
        if (found) {
            return found;
        }
    }

    if (list2) {
        found = bsearch(&value, list2, list2_size, sizeof(ws_services_entry_t), compare_entry);
        if (found) {
            return found;
        }
    }

    return NULL;
}

void
global_services_dump(FILE *fp)
{
    ws_services_entry_t const *ptr;

    /* Brute-force approach... */
    for (uint16_t num = 0; num <= _services_max_port && num < UINT16_MAX; num++) {
        /* TCP */
        ptr = global_services_lookup(num, ws_tcp);
        if (ptr != NULL) {
            fprintf(fp, "%s\t%"PRIu16"\ttcp\t%s\n", ptr->name, num, ptr->description);
        }
        /* UDP */
        ptr = global_services_lookup(num, ws_udp);
        if (ptr != NULL) {
            fprintf(fp, "%s\t%"PRIu16"\tudp\t%s\n", ptr->name, num, ptr->description);
        }
        /* SCTP */
        ptr = global_services_lookup(num, ws_sctp);
        if (ptr != NULL) {
            fprintf(fp, "%s\t%"PRIu16"\tsctp\t%s\n", ptr->name, num, ptr->description);
        }
        /* DCCP */
        ptr = global_services_lookup(num, ws_dccp);
        if (ptr != NULL) {
            fprintf(fp, "%s\t%"PRIu16"\tdccp\t%s\n", ptr->name, num, ptr->description);
        }
    }
}
