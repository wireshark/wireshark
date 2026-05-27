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
#pragma once
#include <epan/prefs.h>
#include <wsutil/inet_addr.h>
#include "ws_symbol_export.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/**
 * @brief Holds the result of a MaxMind database (MMDB) geolocation and ASN lookup for a single IP address.
 */
typedef struct _mmdb_lookup_t {
    bool        found;       /**< True if the lookup produced a result; false if the IP address was not found in the database. */
    const char* country;     /**< Full name of the country associated with the IP address, or NULL if unavailable. */
    const char* country_iso; /**< ISO 3166-1 alpha-2 country code (e.g. "US", "DE"), or NULL if unavailable. */
    const char* city;        /**< City name associated with the IP address, or NULL if unavailable. */
    uint32_t    as_number;   /**< Autonomous System (AS) number associated with the IP address, or 0 if unavailable. */
    const char* as_org;      /**< Name of the organization owning the AS, or NULL if unavailable. */
    double      latitude;    /**< Geographic latitude of the IP address location in decimal degrees. */
    double      longitude;   /**< Geographic longitude of the IP address location in decimal degrees. */
    uint16_t    accuracy;    /**< Estimated accuracy radius of the geolocation result, in kilometers. */
} mmdb_lookup_t;

/**
 * @brief Init / reset function called from prefs_reset.
 *
 * @param nameres The name resolution preferences module.
 */
WS_DLL_LOCAL void maxmind_db_pref_init(module_t *nameres);

/**
 * @brief Cleanup function called from prefs_cleanup.
 */
WS_DLL_LOCAL void maxmind_db_pref_cleanup(void);

/**
 * @brief Apply preferences for MaxMind database resolution.
 */
WS_DLL_LOCAL void maxmind_db_pref_apply(void);

/**
 * @brief Look up an IPv4 address in a database
 *
 * @param addr IPv4 address to look up
 *
 * @return The database entry if found, else NULL.
 */
WS_DLL_PUBLIC WS_RETNONNULL const mmdb_lookup_t *maxmind_db_lookup_ipv4(const ws_in4_addr *addr);

/**
 * @brief Look up an IPv6 address in a database
 *
 * @param addr IPv6 address to look up
 *
 * @return The database entry if found, else NULL.
 */
WS_DLL_PUBLIC WS_RETNONNULL const mmdb_lookup_t *maxmind_db_lookup_ipv6(const ws_in6_addr *addr);

/**
 * @brief Get all configured paths
 *
 * @return String with all paths separated by a path separator. The string
 * must be freed.
 */
WS_DLL_PUBLIC char *maxmind_db_get_paths(void);

/**
 * @brief Process outstanding requests.
 *
 * @return True if any new addresses were resolved.
 */
WS_DLL_LOCAL bool maxmind_db_lookup_process(void);

/**
 * @brief Checks whether the lookup result was successful and has valid coordinates.
 *
 * @param result The lookup result to check.
 * @return True if the lookup was successful and has valid coordinates, false otherwise.
 */
static inline bool maxmind_db_has_coords(const mmdb_lookup_t *result)
{
    return result && result->found &&
        result->longitude != DBL_MAX && result->latitude != DBL_MAX;
}

/**
 * @brief Select whether lookups should be performed synchronously.
 *
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
