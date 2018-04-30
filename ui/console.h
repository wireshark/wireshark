/* console.h
 * Console log handler routines
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __CONSOLE_H__
#define __CONSOLE_H__

#ifdef _WIN32 /* Needed for console I/O */
#include <fcntl.h>
#include <conio.h>
#include <ui/win32/console_win32.h>
#endif

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/** Set the console log handler.
 */
void set_console_log_handler(void);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __CONSOLE_H__ */

/*
 * Editor modelines
 *
 * Local Variables:
 * c-basic-offset: 4
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * ex: set shiftwidth=4 tabstop=8 expandtab:
 * :indentSize=4:tabSize=8:noTabs=true:
 */
