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
 * Called when the program starts, to enable security features and save
 * whatever credential information we'll need later.
 */
WS_DLL_PUBLIC void init_process_policies(void);

/**
 * Was this program started with special privileges?  get_credential_info()
 * MUST be called before calling this.
 * @return true if the program was started with special privileges,
 * false otherwise.
 */
WS_DLL_PUBLIC bool started_with_special_privs(void);

/**
 * Is this program running with special privileges? get_credential_info()
 * MUST be called before calling this.
 * @return true if the program is running with special privileges,
 * false otherwise.
 */
WS_DLL_PUBLIC bool running_with_special_privs(void);

/**
 * Permanently relinquish special privileges. get_credential_info()
 * MUST be called before calling this.
 */
WS_DLL_PUBLIC void relinquish_special_privs_perm(void);

/**
 * Get the current username.  String must be g_free()d after use.
 * @return A freshly g_alloc()ed string containing the username,
 * or "UNKNOWN" on failure.
 */
WS_DLL_PUBLIC char *get_cur_username(void);

/**
 * Get the current group.  String must be g_free()d after use.
 * @return A freshly g_alloc()ed string containing the group,
 * or "UNKNOWN" on failure.
 */
WS_DLL_PUBLIC char *get_cur_groupname(void);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __PRIVILEGES_H__ */
