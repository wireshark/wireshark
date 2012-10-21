/* console_win32.h
 * Console support for MSWindows
 *
 * $Id$
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 2002, Jeffrey C. Foster <jfoste@woodward.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
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

/** Set console wait.
 * @param console_wait set/no set console wait
 */
void set_console_wait(gboolean console_wait);
/** get console wait
 * @return set/no set console wait
 */
gboolean get_console_wait(void);

/** Set has console.
 * @param has_console set/no set has_console
 */
void set_has_console(gboolean has_console);

gboolean get_has_console(void);

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
 * Editor modelines
 *
 * Local Variables:
 * c-basic-offset: 2
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * ex: set shiftwidth=2 tabstop=8 expandtab:
 * :indentSize=2:tabSize=8:noTabs=true:
 */
