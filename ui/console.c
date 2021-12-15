/* console.c
 * Console log handler routines
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <stdio.h>


#include "epan/prefs.h"
#include "wsutil/time_util.h"
#include <wsutil/ws_assert.h>

#include "console.h"

void
console_log_writer(const char *domain, enum ws_log_level level,
                                   struct timespec timestamp,
                                   const char *file, int line, const char *func,
                                   const char *user_format, va_list user_ap,
                                   void *user_data _U_)
{
    gboolean fatal = level == LOG_LEVEL_ERROR;

#ifdef _WIN32
    if (prefs.gui_console_open != console_open_never || fatal) {
        /* the user wants a console or the application will terminate immediately */
        create_console();
    }
#else
    (void)fatal;
#endif /* _WIN32 */

    ws_log_console_writer(domain, level, timestamp, file, line, func,
                                user_format, user_ap);

#ifdef _WIN32
    if (fatal) {
        /* wait for a key press before the following error handler will terminate the program
            this way the user at least can read the error message */
        printf("\n\nPress any key to exit\n");
        _getch();
    }
#endif /* _WIN32 */
}
