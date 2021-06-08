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

#include "console.h"

void
console_log_writer(const char *message, enum ws_log_domain domain _U_,
                    enum ws_log_level level, void *ptr _U_)
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

    FILE *fp = stderr;
    g_assert(message);

    fputs(message, fp);
    fputc('\n', fp);
    fflush(fp);

#ifdef _WIN32
    if (fatal) {
        /* wait for a key press before the following error handler will terminate the program
            this way the user at least can read the error message */
        printf("\n\nPress any key to exit\n");
        _getch();
    }
#endif /* _WIN32 */
}
