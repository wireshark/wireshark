/* console_win32.c
 * Console support for MSWindows
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

#include <fcntl.h>
#include <conio.h>
#include <windows.h>
#include <tchar.h>

static gboolean has_console;  /* TRUE if app has console */
static gboolean console_wait; /* "Press any key..." */
static gboolean stdin_capture = FALSE; /* Don't grab stdin & stdout if TRUE */

/*
 * Check whether a given standard handle needs to be redirected.
 *
 * If you run a Windows-subsystem program from cmd.exe on Windows XP,
 * and you haven't redirected the handle in question, GetStdHandle()
 * succeeds (so it doesn't return INVALID_HANDLE_VALUE or NULL), but
 * GetFile_type fails on the results with ERROR_INVALID_HANDLE.
 * In that case, redirection to a console is necessary.
 *
 * If you run it from the shell prompt in "mintty" in at least some
 * versions of Cygwin on Windows XP, and you haven't redirected the
 * handle in question, GetStdHandle() succeeds and returns a handle
 * that's a pipe or socket; it appears mintty reads from it and outputs
 * what it reads to the console.
 */
static gboolean
needs_redirection(int std_handle)
{
	HANDLE fd;
	DWORD handle_type;
	DWORD error;

	fd = GetStdHandle(std_handle);
	if (fd == NULL) {
		/*
		 * No standard handle.  According to Microsoft's
		 * documentation for GetStdHandle(), one reason for
		 * this would be that the process is "a service on
		 * an interactive desktop"; I'm not sure whether
		 * such a process should be popping up a console.
		 *
		 * However, it also appears to be the case for
		 * the standard input and standard error, but
		 * *not* the standard output, for something run
		 * with a double-click in Windows Explorer,
		 * sow we'll say it needs redirection.
		 */
		return TRUE;
	}
	if (fd == INVALID_HANDLE_VALUE) {
		/*
		 * OK, I'm not when this would happen; return
		 * "no redirection" for now.
		 */
		return FALSE;
	}
	handle_type = GetFileType(fd);
	if (handle_type == FILE_TYPE_UNKNOWN) {
		error = GetLastError();
		if (error == ERROR_INVALID_HANDLE) {
			/*
			 * OK, this appears to be the case where we're
			 * running something in a mode that needs a
			 * console.
			 */
			return TRUE;
		}
	}

	/*
	 * Assume no redirection is needed for all other cases.
	 */
	return FALSE;
}

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
  gboolean must_redirect_stdin;
  gboolean must_redirect_stdout;
  gboolean must_redirect_stderr;

  if (stdin_capture) {
    /* We've been handed "-i -". Don't mess with stdio. */
    return;
  }

  if (!has_console) {
    /* Are the standard input, output, and error invalid handles? */
    must_redirect_stdin = needs_redirection(STD_INPUT_HANDLE);
    must_redirect_stdout = needs_redirection(STD_OUTPUT_HANDLE);
    must_redirect_stderr = needs_redirection(STD_ERROR_HANDLE);

    /* If none of them are invalid, we don't need to do anything. */
    if (!must_redirect_stdin && !must_redirect_stdout && !must_redirect_stderr)
      return;

    /* OK, at least one of them needs to be redirected to a console;
       try to attach to the parent process's console and, if that fails,
       try to create one. */
    /*
     * See if we have an existing console (i.e. we were run from a
     * command prompt).
     */
    if (!AttachConsole(ATTACH_PARENT_PROCESS)) {
      /* Probably not, as we couldn't attach to the parent process's console.
         Try to create a console.

         According to a comment on

             http://msdn.microsoft.com/en-us/library/windows/desktop/ms681952(v=vs.85).aspx

         and according to

             http://connect.microsoft.com/VisualStudio/feedback/details/689696/installing-security-update-kb2507938-prevents-console-allocation

         and

             http://answers.microsoft.com/en-us/windows/forum/windows_xp-windows_update/kb2567680-andor-kb2507938-breaks-attachconsole-api/e8191280-2d49-4be4-9918-18486fba0afa

         even a failed attempt to attach to another process's console
         will cause subsequent AllocConsole() calls to fail, possibly due
         to bugs introduced by a security patch.  To work around this, we
         do a FreeConsole() first. */
      FreeConsole();
      if (AllocConsole()) {
        /* That succeeded. */
        console_wait = TRUE;
        SetConsoleTitle(_T("Wireshark Debug Console"));
      } else {
        /* On Windows XP, this still fails; FreeConsole() apparently
           doesn't clear the state, as it does on Windows 7. */
        return;   /* couldn't create console */
      }
    }

    if (must_redirect_stdin)
      ws_freopen("CONIN$", "r", stdin);
    if (must_redirect_stdout) {
      ws_freopen("CONOUT$", "w", stdout);
      fprintf(stdout, "\n");
    }
    if (must_redirect_stderr) {
      ws_freopen("CONOUT$", "w", stderr);
      fprintf(stderr, "\n");
    }

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
