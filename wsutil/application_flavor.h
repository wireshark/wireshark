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
#include <wiretap/wtap.h>

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
 * @brief Get the prefix for the application specific environment variable used to retrieve various configurations.
 *
 * @return The application prefix.
 */
WS_DLL_PUBLIC const char* application_configuration_environment_prefix(void);

/**
 * @brief Get the list of application supported file extensions
 *
 * @param file_extensions Returned array of extensions supported by the application
 * @param num_extensions Returned number of extensions supported by the application
 */
WS_DLL_PUBLIC void application_file_extensions(const struct file_extension_info** file_extensions, unsigned* num_extensions);

/**
 * @brief Get the default columns for the application
 */
WS_DLL_PUBLIC const char** application_columns(void);

/**
 * @brief Get the default number of columns for the application
 */
WS_DLL_PUBLIC unsigned application_num_columns(void);

/**
 * @brief Convenience routine for checking the application flavor.
 * @return true if the application flavor is APPLICATION_FLAVOR_WIRESHARK.
 */
WS_DLL_PUBLIC bool application_flavor_is_wireshark(void);

#ifdef __cplusplus
}
#endif /* __cplusplus */
