/** @file
 * Declarations of routines returning strings to use when reporting a bug.
 * They ask the user to report a bug to the Wireshark developers.
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __PLEASE_REPORT_BUG_H__
#define __PLEASE_REPORT_BUG_H__

#include "ws_symbol_export.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/**
 * @brief Returns a long bug report message.
 *
 * Provides a detailed message encouraging users to report unexpected behavior.
 * Intended for use in alert dialogs, logs, or printed output.
 *
 * @return A pointer to a static string containing the full bug report message.
 */
WS_DLL_PUBLIC const char *please_report_bug(void);

/**
 * @brief Returns a short bug report message.
 *
 * Provides a concise message suitable for status bars or compact UI elements.
 *
 * @return A pointer to a static string containing the short bug report message.
 */
WS_DLL_PUBLIC const char *please_report_bug_short(void);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __PLEASE_REPORT_BUG_H__ */
