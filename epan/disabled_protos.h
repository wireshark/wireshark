/* disabled_protos.h
 * Declarations of routines for reading and writing protocols file that determine
 * enabling and disabling of protocols.
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef DISABLED_PROTOS_H
#define DISABLED_PROTOS_H

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/*
 * Disable a particular protocol by name
 */
WS_DLL_PUBLIC void
proto_disable_proto_by_name(const char *name);

/*
 * Enable a particular protocol by name.  This will only enable
 * protocols that are disabled by default.  All others will be ignored.
 */
WS_DLL_PUBLIC void
proto_enable_proto_by_name(const char *name);

/*
 * Enable/disable a particular heuristic dissector by name
 * On success (found the protocol), return TRUE.
 * On failure (didn't find the protocol), return FALSE.
 */
WS_DLL_PUBLIC gboolean
proto_enable_heuristic_by_name(const char *name, gboolean enable);

/*
 * Read the files that enable and disable protocols and heuristic
 * dissectors.  Report errors through the UI.
 *
 * This is called by epan_load_settings(); programs should call that
 * rather than individually calling the routines it calls.
 */
extern void
read_enabled_and_disabled_lists(void);

/*
 * Write out the lists of enabled and disabled protocols and heuristic
 * dissectors to the corresponding files.  Report errors through the UI.
 */
WS_DLL_PUBLIC void
save_enabled_and_disabled_lists(void);

/*
 * Free the internal structures
 */
extern void
cleanup_enabled_and_disabled_lists(void);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* DISABLED_PROTOS_H */
