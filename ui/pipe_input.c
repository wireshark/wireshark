/* pipe_input.c
 * Pipe input routines. Declared in pipe_input.h
 *
 * $Id$
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

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <glib.h>

#include "pipe_input.h"

#ifdef _WIN32
#include <windows.h>
#include <io.h>
#endif

#ifdef HAVE_LIBPCAP

typedef struct pipe_input_tag {
    gint                source;
    gpointer            user_data;
    int                 *child_process;
    pipe_input_cb_t     input_cb;
    guint               pipe_input_id;
#ifdef _WIN32
#else
    GIOChannel          *channel;
#endif
} pipe_input_t;


#ifdef _WIN32
/* The timer has expired, see if there's stuff to read from the pipe,
   if so, do the callback */
static gboolean
pipe_timer_cb(gpointer data)
{
    HANDLE handle;
    DWORD avail = 0;
    gboolean result, result1;
    DWORD childstatus;
    pipe_input_t *pipe_input = data;
    gint iterations = 0;


    /* try to read data from the pipe only 5 times, to avoid blocking */
    while(iterations < 5) {
        /*g_log(NULL, G_LOG_LEVEL_DEBUG, "pipe_timer_cb: new iteration");*/

        /* Oddly enough although Named pipes don't work on win9x,
           PeekNamedPipe does !!! */
        handle = (HANDLE) _get_osfhandle (pipe_input->source);
        result = PeekNamedPipe(handle, NULL, 0, NULL, &avail, NULL);

        /* Get the child process exit status */
        result1 = GetExitCodeProcess((HANDLE)*(pipe_input->child_process),
                                     &childstatus);

        /* If the Peek returned an error, or there are bytes to be read
           or the childwatcher thread has terminated then call the normal
           callback */
        if (!result || avail > 0 || childstatus != STILL_ACTIVE) {

            /*g_log(NULL, G_LOG_LEVEL_DEBUG, "pipe_timer_cb: data avail");*/

            if(pipe_input->pipe_input_id != 0) {
                /*g_log(NULL, G_LOG_LEVEL_DEBUG, "pipe_timer_cb: stop timer");*/
                /* avoid reentrancy problems and stack overflow */
                g_source_remove(pipe_input->pipe_input_id);
                pipe_input->pipe_input_id = 0;
            }

            /* And call the real handler */
            if (!pipe_input->input_cb(pipe_input->source, pipe_input->user_data)) {
                g_log(NULL, G_LOG_LEVEL_DEBUG, "pipe_timer_cb: input pipe closed, iterations: %u", iterations);
                /* pipe closed, return false so that the old timer is not run again */
                return FALSE;
            }
        }
        else {
            /*g_log(NULL, G_LOG_LEVEL_DEBUG, "pipe_timer_cb: no data avail");*/
            /* No data, stop now */
            break;
        }

        iterations++;
    }

    if(pipe_input->pipe_input_id == 0) {
        /* restore pipe handler */
        pipe_input->pipe_input_id = g_timeout_add(200, pipe_timer_cb, data);
        /*g_log(NULL, G_LOG_LEVEL_DEBUG, "pipe_timer_cb: finished with iterations: %u, new timer", iterations);*/

        /* Return false so that the old timer is not run again */
        return FALSE;
    } else {
        /*g_log(NULL, G_LOG_LEVEL_DEBUG, "pipe_timer_cb: finished with iterations: %u, old timer", iterations);*/

        /* we didn't stopped the old timer, so let it run */
        return TRUE;
    }
}

#else /* _WIN32 */

/* There's stuff to read from the sync pipe, meaning the child has sent
   us a message, or the sync pipe has closed, meaning the child has
   closed it (perhaps because it exited). */
static gboolean
pipe_input_cb(GIOChannel *source _U_, GIOCondition condition _U_,
               gpointer data)
{
    pipe_input_t *pipe_input = data;


    /* avoid reentrancy problems and stack overflow */
    g_source_remove(pipe_input->pipe_input_id);

    if (pipe_input->input_cb(pipe_input->source, pipe_input->user_data)) {
        /* restore pipe handler */
        pipe_input->pipe_input_id = g_io_add_watch_full (pipe_input->channel,
                                                         G_PRIORITY_HIGH,
                                                         G_IO_IN|G_IO_ERR|G_IO_HUP,
                                                         pipe_input_cb,
                                                         pipe_input,
                                                         NULL);
    }
    return TRUE;
}
#endif

void pipe_input_set_handler(gint source, gpointer user_data, int *child_process, pipe_input_cb_t input_cb)
{
    static pipe_input_t pipe_input;

    pipe_input.source        = source;
    pipe_input.child_process = child_process;
    pipe_input.user_data     = user_data;
    pipe_input.input_cb      = input_cb;

#ifdef _WIN32
    /* Tricky to use pipes in win9x, as no concept of wait.  NT can
       do this but that doesn't cover all win32 platforms.  GTK can do
       this but doesn't seem to work over processes.  Attempt to do
       something similar here, start a timer and check for data on every
       timeout. */
       /*g_log(NULL, G_LOG_LEVEL_DEBUG, "pipe_input_set_handler: new");*/
    pipe_input.pipe_input_id = g_timeout_add(200, pipe_timer_cb, &pipe_input);
#else /* _WIN32 */
    pipe_input.channel = g_io_channel_unix_new(source);
    g_io_channel_set_encoding(pipe_input.channel, NULL, NULL);
    pipe_input.pipe_input_id = g_io_add_watch_full(pipe_input.channel,
                                                   G_PRIORITY_HIGH,
                                                   G_IO_IN|G_IO_ERR|G_IO_HUP,
                                                   pipe_input_cb,
                                                   &pipe_input,
                                                   NULL);
#endif /* _WIN32 */
}

#endif /* HAVE_LIBPCAP */
