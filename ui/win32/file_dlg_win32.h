/** @file
 *
 * Native Windows file dialog routines
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 2006 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __FILE_DLG_WIN32_H__
#define __FILE_DLG_WIN32_H__

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/**
 * @brief set_thread_per_monitor_v2_awareness
 *
 * Qt <= 5.9 supports setting old (Windows 8.1) per-monitor DPI awareness
 * via Qt:AA_EnableHighDpiScaling. We do this in main.cpp. In order for
 * native dialogs to be rendered correctly we need to set per-monitor
 * *v2* awareness prior to creating the dialog, which we can do here.
 * Qt < 5.14(?) or so doesn't render correctly when per-monitor v2 awareness
 * is enabled, so we need to revert our thread context when we're done.
 * Qt >= 6.0 is per-monitor DPI awareness v2 by default, so this doesn't
 * have any effect.
 *
 * @return The current thread DPI awareness context, which should
 * be passed to revert_thread_per_monitor_v2_awareness.
 */
HANDLE set_thread_per_monitor_v2_awareness(void);

/**
 * @brief revert_thread_per_monitor_v2_awareness
 * @param context
 */
void revert_thread_per_monitor_v2_awareness(HANDLE context);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __FILE_DLG_WIN32_H__ */
