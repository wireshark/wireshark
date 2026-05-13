/** @file
 * Declarations of routines for reading and writing protocols file that determine
 * enabling and disabling of protocols.
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#pragma once
#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

#include <ws_symbol_export.h>

/**
 * @brief Check if there are unsaved changes to enabled protocols.
 *
 * Tell if protocols have been enabled/disabled since
 * we've last loaded (or saved) the lists.
 * @return true if there are unsaved changes, false otherwise.
 */
WS_DLL_PUBLIC bool
enabled_protos_unsaved_changes(void);

/**
 * @brief Disable a particular protocol by name.
 * @param name The name of the protocol to disable.
 * @return true if the protocol was successfully disabled, false otherwise.
 */
WS_DLL_PUBLIC bool
proto_disable_proto_by_name(const char *name);

/**
 * @brief Enable a particular protocol by name.
 *
 * @param name The name of the protocol to enable.
 * @return true if the protocol was found and enabled, false otherwise.
 */
WS_DLL_PUBLIC bool
proto_enable_proto_by_name(const char *name);

/**
 * @brief Enable a particular heuristic dissector by name.
 *
 * @param name The name of the heuristic dissector to enable.
 * @return true if the heuristic dissector was successfully enabled, false otherwise.
 */
WS_DLL_PUBLIC bool
proto_enable_heuristic_by_name(const char *name);

/**
 * @brief Disable a heuristic dissector by name.
 *
 * @param name The name of the heuristic dissector to disable.
 * @return true if the heuristic dissector was successfully disabled, false otherwise.
 */
WS_DLL_PUBLIC bool
proto_disable_heuristic_by_name(const char *name);

/**
 * @brief Read the files that enable and disable protocols and heuristic
 * dissectors.  Report errors through the UI.
 *
 * This is called by epan_load_settings(); programs should call that
 * rather than individually calling the routines it calls.
 * This is only public (instead of extern) to allow users who temporarily
 * disable protocols in the PHS GUI to re-enable them.
 *
 * @param app_env_var_prefix Prefix for application environment variables.
 */
WS_DLL_PUBLIC void
read_enabled_and_disabled_lists(const char* app_env_var_prefix);

/**
 * @brief Write out the lists of enabled and disabled protocols and heuristic
 * dissectors to the corresponding files.  Report errors through the UI.
 *
 * @param app_env_var_prefix Prefix for application environment variables.
 */
WS_DLL_PUBLIC void
save_enabled_and_disabled_lists(const char* app_env_var_prefix);

/**
 * @brief Cleans up enabled and disabled protocol lists.
 *
 * This function iterates through and frees the memory allocated for the
 * disabled heuristics and protocols lists.
 */
extern void
cleanup_enabled_and_disabled_lists(void);

#ifdef __cplusplus
}
#endif /* __cplusplus */
