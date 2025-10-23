/** @file
 * Declarations of outines to report operating system version information
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __WSUTIL_OS_VERSION_INFO_H__
#define __WSUTIL_OS_VERSION_INFO_H__

#include <wireshark.h>

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/**
 * @brief Appends the operating system version information to a GString.
 *
 * Retrieves the current operating system's version details and appends them
 * to the provided GString. This may include the OS name, version number,
 * and build information depending on platform support.
 *
 * @param str Pointer to a GString where the OS version info will be appended.
 */
WS_DLL_PUBLIC void get_os_version_info(GString *str);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __WSUTIL_OS_VERSION_INFO_H__ */
