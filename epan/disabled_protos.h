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

#ifndef DISABLED_PROTOS_H
#define DISABLED_PROTOS_H

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

#include <glib.h>
#include <ws_symbol_export.h>

/*
 * Tell if protocols have been enabled/disabled since
 * we've last loaded (or saved) the lists.
 */
WS_DLL_PUBLIC bool
enabled_protos_unsaved_changes(void);

/*
 * Disable a particular protocol by name
 * On success (found the protocol), return true.
 * On failure (didn't find the protocol), return false.
 */
WS_DLL_PUBLIC bool
proto_disable_proto_by_name(const char *name);

/*
 * Enable a particular protocol by name
 * On success (found the protocol), return true.
 * On failure (didn't find the protocol), return false.
 */
WS_DLL_PUBLIC bool
proto_enable_proto_by_name(const char *name);

/*
 * Enable a particular heuristic dissector by name
 * On success (found the protocol), return true.
 * On failure (didn't find the protocol), return false.
 */
WS_DLL_PUBLIC bool
proto_enable_heuristic_by_name(const char *name);

/*
 * Disable a particular heuristic dissector by name
 * On success (found the protocol), return true.
 * On failure (didn't find the protocol), return false.
 */
WS_DLL_PUBLIC bool
proto_disable_heuristic_by_name(const char *name);

/*
 * Read the files that enable and disable protocols and heuristic
 * dissectors.  Report errors through the UI.
 *
 * This is called by epan_load_settings(); programs should call that
 * rather than individually calling the routines it calls.
 * This is only public (instead of extern) to allow users who temporarily
 * disable protocols in the PHS GUI to re-enable them.
 */
WS_DLL_PUBLIC void
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
