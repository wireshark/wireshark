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
 * @brief Initialize our application flavor by name
 *
 * Set our application flavor, which determines the top-level
 * configuration directory name and environment variable prefixes.
 * Default is APPLICATION_FLAVOR_WIRESHARK.
 *
 * @param app_name Application name to determine flavor.
 */
WS_DLL_PUBLIC void set_application_flavor_by_name(const char* app_name);

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
 * @brief Get the application specific environment variable used to retrieve configuration.
 *
 * @param suffix The suffix appended to the application specific environment variable
 * @return The application name. Must be freed.
 */
WS_DLL_PUBLIC char* application_configuration_environment_variable(const char* suffix);

/**
 * @brief Get the application specific directory where extcaps can be found
 *
 * @param install_prefix The prefix prepended to the extcap directory
 * @return The application directory name. Must be freed.
 */
WS_DLL_PUBLIC char* application_extcap_dir(const char* install_prefix);

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
