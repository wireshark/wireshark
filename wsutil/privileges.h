/** @file
 * Declarations of routines for handling privileges.
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 2006 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __PRIVILEGES_H__
#define __PRIVILEGES_H__

#include <wireshark.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Initializes process-level security policies.
 *
 * Called during program startup to enable security features and capture
 * credential information needed for privilege checks and user context.
 */
WS_DLL_PUBLIC void init_process_policies(void);

/**
 * @brief Checks whether the program was started with special privileges.
 *
 * Requires a prior call to get_credential_info(). This function determines
 * whether the process originally launched with special privileges (e.g., root).
 *
 * @return true if the program started with special privileges, false otherwise.
 */
WS_DLL_PUBLIC bool started_with_special_privs(void);

/**
 * @brief Checks whether the program is currently running with special privileges.
 *
 * Requires a prior call to get_credential_info(). This function determines
 * whether the process still retains special privileges at runtime.
 *
 * @return true if the program is currently running with special privileges, false otherwise.
 */
WS_DLL_PUBLIC bool running_with_special_privs(void);

/**
 * @brief Permanently drops any special privileges.
 *
 * Requires a prior call to get_credential_info(). This function relinquishes
 * special privileges for the remainder of the process lifetime.
 */
WS_DLL_PUBLIC void relinquish_special_privs_perm(void);

/**
 * @brief Retrieves the current username.
 *
 * Returns the current username of the process. The returned string must be
 * freed with g_free() after use.
 *
 * @return A newly allocated string containing the username, or "UNKNOWN" on failure.
 */
WS_DLL_PUBLIC char *get_cur_username(void);

/**
 * @brief Retrieves the current group name.
 *
 * Returns the current group name of the process. The returned string must be
 * freed with g_free() after use.
 *
 * @return A newly allocated string containing the group name, or "UNKNOWN" on failure.
 */
WS_DLL_PUBLIC char *get_cur_groupname(void);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __PRIVILEGES_H__ */
