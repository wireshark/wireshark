/* ui_util.c
 * UI utility routines
 *
 * $Id: ui_util.c,v 1.19 2004/02/13 00:53:37 guy Exp $
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@ethereal.com>
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */

/* Originally copied from gtk/ui_util.c */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <stdio.h>

#include <windows.h>

#include <io.h>

#include <epan/prefs.h>
#include "prefs-recent.h"
#include "epan/epan.h"
#include "../../ui_util.h"

#include "win32-globals.h"
#include "win32-element.h"

#ifdef HAVE_LIBPCAP

#define PIPE_ID 1000

/* Called during the capture loop.  Update our windows. */
void main_window_update(void)
{
    MSG              msg;

    while(PeekMessage(&msg, NULL, 0, 0, PM_REMOVE)) {
	TranslateMessage(&msg);
	DispatchMessage(&msg);
    }
}

typedef struct pipe_input_tag {
    gint                source;
    gpointer            user_data;
    int                 *child_process;
    pipe_input_cb_t     input_cb;
    /* XXX - Since we're using PIPE_ID every time, do we need this? */
    UINT                pipe_input_id;
} pipe_input_t;


/* The timer has expired, see if there's stuff to read from the pipe,
   if so, do the callback */
static VOID CALLBACK
pipe_timer_cb(HWND hwnd, UINT u_msg, UINT id_event, DWORD time)
{
  HANDLE handle;
  DWORD avail = 0;
  gboolean result, result1;
  DWORD childstatus;
  pipe_input_t *pipe_input = win32_element_hwnd_get_data(hwnd, "pipe_input");

  g_assert(pipe_input != NULL);

  /* Oddly enough although Named pipes don't work on win9x,
     PeekNamedPipe does !!! */
  handle = (HANDLE) _get_osfhandle (pipe_input->source);
  result = PeekNamedPipe(handle, NULL, PIPE_ID, NULL, &avail, NULL);

  /* Get the child process exit status */
  result1 = GetExitCodeProcess((HANDLE)*(pipe_input->child_process),
                               &childstatus);

  /* If the Peek returned an error, or there are bytes to be read
     or the childwatcher thread has terminated then call the normal
     callback */
  if (!result || avail > 0 || childstatus != STILL_ACTIVE) {

    /* avoid reentrancy problems and stack overflow */
    KillTimer(g_hw_mainwin, pipe_input->pipe_input_id);

    /* And call the real handler */
    if (pipe_input->input_cb(pipe_input->source, pipe_input->user_data)) {
        /* restore pipe handler */
        pipe_input->pipe_input_id = SetTimer(g_hw_mainwin, PIPE_ID, 200, pipe_timer_cb);
    }
  }
}


void pipe_input_set_handler(gint source, gpointer user_data, int *child_process, pipe_input_cb_t input_cb)
{
    static pipe_input_t pipe_input;

    pipe_input.source        = source;
    pipe_input.child_process = child_process;
    pipe_input.user_data     = user_data;
    pipe_input.input_cb      = input_cb;

    win32_element_hwnd_set_data(g_hw_mainwin, "pipe_input", &pipe_input);

    /* Tricky to use pipes in win9x, as no concept of wait.  NT can
       do this but that doesn't cover all win32 platforms.  GTK can do
       this but doesn't seem to work over processes.  Attempt to do
       something similar here, start a timer and check for data on every
       timeout. */
    pipe_input.pipe_input_id = SetTimer(g_hw_mainwin, PIPE_ID, 200, pipe_timer_cb);
}


#endif /* HAVE_LIBPCAP */

/* exit the main window */
void main_window_exit(void)
{
    PostQuitMessage(0);
}

/* quit a nested main window */
void main_window_nested_quit(void)
{
    PostQuitMessage(0);
}

/* quit the main window */
void main_window_quit(void)
{
    PostQuitMessage(0);
}

/* Retrieve the geometry of a window */
void
window_get_geometry(HWND hwnd, window_geometry_t *geom) {
    LONG wstyle;
    RECT wr;

    GetWindowRect(hwnd, &wr);
    wstyle = GetWindowLong(hwnd, GWL_STYLE);

    geom->x         = wr.left;
    geom->y         = wr.top;
    geom->width     = wr.right - wr.left;
    geom->height    = wr.bottom - wr.top;
    geom->maximized = wstyle & WS_MAXIMIZE;
}

/* Set the geometry of a window */
void
window_set_geometry(HWND hwnd, window_geometry_t *geom) {
    LONG wstyle;

    /* as we now have the geometry from the recent file, set it */
    if (geom->set_pos) {
	SetWindowPos(hwnd, HWND_TOP, geom->x, geom->y, 0, 0,
	    SWP_NOACTIVATE | SWP_NOZORDER | SWP_NOSIZE);
    }

    if (geom->set_size) {
	SetWindowPos(hwnd, HWND_TOP, 0, 0, geom->width, geom->height,
	    SWP_NOACTIVATE | SWP_NOZORDER | SWP_NOMOVE);
    }

    if (geom->set_maximized && geom->maximized) {
	wstyle = GetWindowLong(hwnd, GWL_STYLE);
	SetWindowLong(hwnd, GWL_STYLE, wstyle | WS_MAXIMIZE);
    }
}
