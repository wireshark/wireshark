/** @file
 * Maxmind database support
 *
 * Copyright 2018, Gerald Combs <gerald@wireshark.org>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __MAXMIND_DB_H__
#define __MAXMIND_DB_H__

#include <epan/prefs.h>
#include <wsutil/inet_addr.h>
#include "ws_symbol_export.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

typedef struct _mmdb_lookup_t {
    bool found;
    const char *country;
    const char *country_iso;
    const char *city;
    uint32_t as_number;
    const char *as_org;
    double latitude;
    double longitude;
    uint16_t accuracy;   /** Accuracy radius in kilometers. */
} mmdb_lookup_t;

/**
 * Init / reset function called from prefs_reset
 */
WS_DLL_LOCAL void maxmind_db_pref_init(module_t *nameres);

/**
 * Cleanup function called from prefs_cleanup
 */
WS_DLL_LOCAL void maxmind_db_pref_cleanup(void);

WS_DLL_LOCAL void maxmind_db_pref_apply(void);

/**
 * Look up an IPv4 address in a database
 *
 * @param addr IPv4 address to look up
 *
 * @return The database entry if found, else NULL.
 */
WS_DLL_PUBLIC WS_RETNONNULL const mmdb_lookup_t *maxmind_db_lookup_ipv4(const ws_in4_addr *addr);

/**
 * Look up an IPv6 address in a database
 *
 * @param addr IPv6 address to look up
 *
 * @return The database entry if found, else NULL.
 */
WS_DLL_PUBLIC WS_RETNONNULL const mmdb_lookup_t *maxmind_db_lookup_ipv6(const ws_in6_addr *addr);

/**
 * Get all configured paths
 *
 * @return String with all paths separated by a path separator. The string
 * must be freed.
 */
WS_DLL_PUBLIC char *maxmind_db_get_paths(void);

/**
 * Process outstanding requests.
 *
 * @return True if any new addresses were resolved.
 */
WS_DLL_LOCAL bool maxmind_db_lookup_process(void);

/**
 * Checks whether the lookup result was successful and has valid coordinates.
 */
static inline bool maxmind_db_has_coords(const mmdb_lookup_t *result)
{
    return result && result->found &&
        result->longitude != DBL_MAX && result->latitude != DBL_MAX;
}

/**
 * Select whether lookups should be performed synchronously.
 * Default is asynchronous lookups.
 *
 * @param synchronous Whether maxmind lookups should be synchronous.
 *
 * XXX - if we ever have per-session host name etc. information, we
 * should probably have the "resolve synchronously or asynchronously"
 * flag be per-session, set with an epan API.
 */
WS_DLL_PUBLIC void maxmind_db_set_synchrony(bool synchronous);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __MAXMIND_DB_H__ */

/*
 * Editor modelines
 *
 * Local Variables:
 * c-basic-offset: 4
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * ex: set shiftwidth=4 tabstop=8 expandtab:
 * :indentSize=4:tabSize=8:noTabs=true:
 */
