/* console.c
 * Console log handler routines
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
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

#include "config.h"

#include <stdio.h>


#include "epan/prefs.h"

#include "console.h"

#include "log.h"

static void
console_log_handler(const char *log_domain, GLogLevelFlags log_level,
                    const char *message, gpointer user_data _U_)
{
    time_t curr;
    struct tm *today;
    const char *level;


    /* ignore log message, if log_level isn't interesting based
       upon the console log preferences.
       If the preferences haven't been loaded loaded yet, display the
       message anyway.

       The default console_log_level preference value is such that only
         ERROR, CRITICAL and WARNING level messages are processed;
         MESSAGE, INFO and DEBUG level messages are ignored.  */
    if((log_level & G_LOG_LEVEL_MASK & prefs.console_log_level) == 0 &&
        prefs.console_log_level != 0) {
        return;
    }

#ifdef _WIN32
    if (prefs.gui_console_open != console_open_never || log_level & G_LOG_LEVEL_ERROR) {
        /* the user wants a console or the application will terminate immediately */
        create_console();
    }
    if (get_has_console()) {
        /* For some unknown reason, the above doesn't appear to actually cause
           anything to be sent to the standard output, so we'll just splat the
           message out directly, just to make sure it gets out. */
#endif
        switch(log_level & G_LOG_LEVEL_MASK) {
            case G_LOG_LEVEL_ERROR:
                level = "Err ";
                break;
            case G_LOG_LEVEL_CRITICAL:
                level = "Crit";
                break;
            case G_LOG_LEVEL_WARNING:
                level = "Warn";
                break;
            case G_LOG_LEVEL_MESSAGE:
                level = "Msg ";
                break;
            case G_LOG_LEVEL_INFO:
                level = "Info";
                break;
            case G_LOG_LEVEL_DEBUG:
                level = "Dbg ";
                break;
            default:
                fprintf(stderr, "unknown log_level %d\n", log_level);
                level = NULL;
                g_assert_not_reached();
        }

        /* create a "timestamp" */
        time(&curr);
        today = localtime(&curr);
        if (today != NULL) {
                fprintf(stderr, "%02d:%02d:%02d %8s %s %s\n",
                        today->tm_hour, today->tm_min, today->tm_sec,
                        log_domain != NULL ? log_domain : "",
                        level, message);
        } else {
                fprintf(stderr, "Time not representable %8s %s %s\n",
                        log_domain != NULL ? log_domain : "",
                        level, message);
        }
#ifdef _WIN32
        if(log_level & G_LOG_LEVEL_ERROR) {
            /* wait for a key press before the following error handler will terminate the program
               this way the user at least can read the error message */
            printf("\n\nPress any key to exit\n");
            _getch();
        }
    } else {
        /* XXX - on UN*X, should we just use g_log_default_handler()?
           We want the error messages to go to the standard output;
           on Mac OS X, that will cause them to show up in various
           per-user logs accessible through Console (details depend
           on whether you're running 10.0 through 10.4 or running
           10.5 and later), and, on other UN*X desktop environments,
           if they don't show up in some form of console log, that's
           a deficiency in that desktop environment.  (Too bad
           Windows doesn't set the standard output and error for
           GUI apps to something that shows up in such a log.) */
        g_log_default_handler(log_domain, log_level, message, user_data);
    }
#endif
}

void set_console_log_handler(void)
{
    GLogLevelFlags log_flags;
    /* Arrange that if we have no console window, and a GLib message logging
       routine is called to log a message, we pop up a console window.

       We do that by inserting our own handler for all messages logged
       to the default domain; that handler pops up a console if necessary,
       and then calls the default handler. */

    /* We might want to have component specific log levels later ... */

    log_flags = (GLogLevelFlags)
                (G_LOG_LEVEL_ERROR|
                 G_LOG_LEVEL_CRITICAL|
                 G_LOG_LEVEL_WARNING|
                 G_LOG_LEVEL_MESSAGE|
                 G_LOG_LEVEL_INFO|
                 G_LOG_LEVEL_DEBUG|
                 G_LOG_FLAG_FATAL|
                 G_LOG_FLAG_RECURSION);

    g_log_set_handler(NULL,
                      log_flags,
                      console_log_handler, NULL /* user_data */);
    g_log_set_handler(LOG_DOMAIN_MAIN,
                      log_flags,
                      console_log_handler, NULL /* user_data */);

#ifdef HAVE_LIBPCAP
    g_log_set_handler(LOG_DOMAIN_CAPTURE,
                      log_flags,
                      console_log_handler, NULL /* user_data */);
    g_log_set_handler(LOG_DOMAIN_CAPTURE_CHILD,
                    log_flags,
                    console_log_handler, NULL /* user_data */);

#endif
}

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
