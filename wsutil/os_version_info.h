/* os_version_info.h
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

#include "ws_symbol_export.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/*
 * Get the OS version, and append it to a GString.
 */
WS_DLL_PUBLIC void get_os_version_info(GString *str);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __WSUTIL_OS_VERSION_INFO_H__ */
