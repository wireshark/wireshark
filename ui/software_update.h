/** @file
 *
 * Wrappers and routines to check for software updates.
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __SOFTWARE_UPDATE_H__
#define __SOFTWARE_UPDATE_H__

/** @file
 *  Automatic update routines.
 *
 * Routines that integrate with WinSparkle on Windows and Sparkle on
 * macOS.
 *
 * Sparkle and WinSparkle check for updates by fetching an Appcast XML file from www.wireshark.org.
 * Appcast URLs have the form
 * https://www.wireshark.org/update/<URL version>/<application>/<OS>/<architecture>/en-US/<channel>.xml
 *
 * Where:
 *   URL version: Always 0
 *   Application: One of "Wireshark" or "Stratoshark"
 *   OS: One of :Windows" or "macOS"
 *   Architecture: One of "x86-64" or "arm64"
 *   Channel: One of "stable" or "development"
 *
 * Examples:
 * https://www.wireshark.org/update/0/Wireshark/0.0.0/Windows/x86-64/en-US/stable.xml
 * https://www.wireshark.org/update/0/Wireshark/0.0.0/macOS/arm64/en-US/stable.xml
 * https://www.wireshark.org/update/0/Stratoshark/0.0.0/Windows/x86-64/en-US/stable.xml
 *
 * @ingroup main_ui_group
 */

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/** Initialize software updates.
 *
 * Does nothing on platforms that don't support software updates.
 */
extern void software_update_init(const char* su_application, const char* su_version);

/** Force a software update check.
 *
 * Does nothing on platforms that don't support software updates.
 */
extern void software_update_check(void);

/** Clean up software update checking.
 *
 * Does nothing on platforms that don't support software updates.
 */
extern void software_update_cleanup(void);

#ifdef _WIN32
/** Check to see if Wireshark can shut down safely (e.g. offer to save the
 *  current capture). Called from a separate thread.
 *
 * Does nothing on platforms that don't support software updates.
 */
extern int software_update_can_shutdown_callback(void);

/** Shut down Wireshark in preparation for an upgrade. Called from a separate
 *  thread.
 *
 * Does nothing on platforms that don't support software updates.
 */
extern void software_update_shutdown_request_callback(void);
#endif

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __SOFTWARE_UPDATE_H__ */
