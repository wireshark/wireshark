/* console_win32.h
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

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

#ifdef _WIN32

/** @file
 * Win32 specific console.
 */

/** Create Windows console.
 *
 */
void create_console(void);

/** Destroy Windows console.
 *
 */
void destroy_console(void);

/** Set console wait. GTK+ only.
 * @param console_wait set/no set console wait
 */
void set_console_wait(gboolean console_wait);
/** get console wait
 * @return set/no set console wait
 */
gboolean get_console_wait(void);

/** Set stdin capture.
 * @param console_wait set/no stdin_capture
 */
void set_stdin_capture(gboolean set_stdin_capture);

/** get stdin caputre
 * @return set/no set stdin_capture
 */
gboolean get_stdin_capture(void);
#endif/* _WIN32 */

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __CONSOLE_WIN32_H__ */

/*
 * Editor modelines  -  https://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 4
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * vi: set shiftwidth=4 tabstop=8 expandtab:
 * :indentSize=4:tabSize=8:noTabs=true:
 */
