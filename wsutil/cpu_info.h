/** @file
 * Declarations of routines to report CPU information
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __WSUTIL_CPU_INFO_H__
#define __WSUTIL_CPU_INFO_H__

#include <wireshark.h>

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/**
 * @brief Append detailed CPU information to a GString buffer.
 *
 * Retrieves system-specific CPU details such as model name, architecture,
 * core count, and feature flags, and appends them to the provided `GString`.
 *
 * @param str Pointer to a `GString` buffer where CPU information will be appended.
 */
WS_DLL_PUBLIC void get_cpu_info(GString *str);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __WSUTIL_CPU_INFO_H__ */
