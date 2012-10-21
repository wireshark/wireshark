/* console_win32.c
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
 *
 *
 */

#ifdef _WIN32

#include <string.h>
#include <stdio.h>
#include <stdlib.h>

#include <glib.h>
#include <wsutil/file_util.h>

#include "console_win32.h"
#include "../../console_io.h"

#if _MSC_VER < 1500
/* AttachConsole() needs this #define! */
#define _WIN32_WINNT 0x0501
#endif
#include <fcntl.h>
#include <conio.h>
#include <windows.h>
#include <tchar.h>

static gboolean has_console;  /* TRUE if app has console */
static gboolean console_wait; /* "Press any key..." */
static gboolean stdin_capture = FALSE; /* Don't grab stdin & stdout if TRUE */

/* The code to create and desstroy console windows should not be necessary,
   at least as I read the GLib source code, as it looks as if GLib is, on
   Win32, *supposed* to create a console window into which to display its
   output.

   That doesn't happen, however.  I suspect there's something completely
   broken about that code in GLib-for-Win32, and that it may be related
   to the breakage that forces us to just call "printf()" on the message
   rather than passing the message on to "g_log_default_handler()"
   (which is the routine that does the aforementioned non-functional
   console window creation).  */

/*
 * If this application has no console window to which its standard output
 * would go, create one.
 */
void
create_console(void)
{
  if (stdin_capture) {
    /* We've been handed "-i -". Don't mess with stdio. */
    return;
  }

  if (!has_console) {
    /* We have no console to which to print the version string, so
       create one and make it the standard input, output, and error. */

    /*
     * See if we have an existing console (i.e. we were run from a
     * command prompt)
     */
    if (!AttachConsole(ATTACH_PARENT_PROCESS)) {
      if (AllocConsole()) {
        console_wait = TRUE;
        SetConsoleTitle(_T("Wireshark Debug Console"));
      } else {
        return;   /* couldn't create console */
      }
    }

    ws_freopen("CONIN$", "r", stdin);
    ws_freopen("CONOUT$", "w", stdout);
    ws_freopen("CONOUT$", "w", stderr);
    fprintf(stdout, "\n");
    fprintf(stderr, "\n");

    /* Now register "destroy_console()" as a routine to be called just
       before the application exits, so that we can destroy the console
       after the user has typed a key (so that the console doesn't just
       disappear out from under them, giving the user no chance to see
       the message(s) we put in there). */
    atexit(destroy_console);

    /* Well, we have a console now. */
    has_console = TRUE;
  }
}

void
destroy_console(void)
{
  if (console_wait) {
    printf("\n\nPress any key to exit\n");
    _getch();
  }
  FreeConsole();
}

void
set_console_wait(gboolean set_console_wait)
{
  console_wait = set_console_wait;
}

gboolean
get_console_wait(void)
{
  return console_wait;
}

void
set_has_console(gboolean set_has_console)
{
  has_console = has_console;
}

gboolean
get_has_console(void)
{
  return has_console;
}

void
set_stdin_capture(gboolean set_stdin_capture)
{
  stdin_capture = set_stdin_capture;
}

gboolean
get_stdin_capture(void)
{
  return stdin_capture;
}

#endif /* _WIN32 */

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
