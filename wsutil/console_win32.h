/** @file
 *
 * Console support for MSWindows
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 2002, Jeffrey C. Foster <jfoste@woodward.com>
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __CONSOLE_WIN32_H__
#define __CONSOLE_WIN32_H__

#include <wireshark.h>

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

#ifdef _WIN32

/** @file
 * Win32 specific console.
 */

/**
 * @brief Create Windows console.
 */
WS_DLL_PUBLIC
void create_console(void);

/**
 * @brief Connect to stdio if available.
 */
WS_DLL_PUBLIC
void restore_pipes(void);

/**
 * @brief Destroy Windows console.
 */
WS_DLL_PUBLIC
void destroy_console(void);

/**
 * @brief Set console wait.
 * @param console_wait set/no set console wait
 */
WS_DLL_PUBLIC
void set_console_wait(bool console_wait);

/**
 * @brief get console wait
 * @return set/no set console wait
 */
WS_DLL_PUBLIC
bool get_console_wait(void);

/**
 * @brief Set stdin capture.
 * @param set_stdin_capture whether to enable stdin capture
 */
WS_DLL_PUBLIC
void set_stdin_capture(bool set_stdin_capture);

/**
 * @brief get stdin capture
 * @return set/no set stdin_capture
 */
WS_DLL_PUBLIC
bool get_stdin_capture(void);
#endif/* _WIN32 */

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __CONSOLE_WIN32_H__ */
