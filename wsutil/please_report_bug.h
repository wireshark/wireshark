/* please_report_bug.h
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

/*
 * Long message, to use in alert boxes and printed messages.
 */
WS_DLL_PUBLIC const char *please_report_bug(void);

/*
 * Short message, to use in status bar messages.
 */
WS_DLL_PUBLIC const char *please_report_bug_short(void);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __PLEASE_REPORT_BUG_H__ */
