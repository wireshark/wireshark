/** @file
 * Application flavor definitions
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#pragma once

#include <wireshark.h>

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/*
 * Application flavor. Used to construct configuration
 * paths and environment variables.
 */
enum application_flavor_e {
    APPLICATION_FLAVOR_WIRESHARK,
    APPLICATION_FLAVOR_STRATOSHARK,
};

/**
 * @brief Initialize our application flavor.
 *
 * Set our application flavor, which determines the top-level
 * configuration directory name and environment variable prefixes.
 * Default is APPLICATION_FLAVOR_WIRESHARK.
 *
 * @param flavor Application flavor.
 */
WS_DLL_PUBLIC void set_application_flavor(enum application_flavor_e flavor);

/**
 * @brief Get our application flavor.
 * @return The flavor.
 */
WS_DLL_PUBLIC enum application_flavor_e get_application_flavor(void);

/**
 * @brief Get the proper (capitalized) application name, suitable for user
 * presentation.
 *
 * @return The application name. Must not be freed.
 */
WS_DLL_PUBLIC const char *application_flavor_name_proper(void);

/**
 * @brief Get the lower-case application name.
 *
 * @return The application name. Must not be freed.
 */
WS_DLL_PUBLIC const char *application_flavor_name_lower(void);

/**
 * @brief Get an application flavor from its name.
 *
 * @param name The application name. Case insensitive.
 * @return The application flavor, or APPLICATION_FLAVOR_WIRESHARK if there is no match.
 */
WS_DLL_PUBLIC enum application_flavor_e application_name_to_flavor(const char * name);

/**
 * @brief Convenience routine for checking the application flavor.
 * @return true if the application flavor is APPLICATION_FLAVOR_WIRESHARK.
 */
WS_DLL_PUBLIC bool application_flavor_is_wireshark(void);

/**
 * @brief Convenience routine for checking the application flavor.
 * @return true if the application flavor is APPLICATION_FLAVOR_STRATOSHARK.
 */
WS_DLL_PUBLIC bool application_flavor_is_stratoshark(void);

#ifdef __cplusplus
}
#endif /* __cplusplus */
