/* ws_pipe.c
 *
 * Routines for handling pipes.
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include <config.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
#include <windows.h>
#include <io.h>
#else
#include <unistd.h>
#ifdef HAVE_SYS_SELECT_H
#include <sys/select.h>
#endif
#endif

#include <glib.h>
#include <log.h>

#include "wsutil/ws_pipe.h"

gboolean
ws_pipe_data_available(int pipe_fd)
{
#ifdef _WIN32 /* PeekNamedPipe */
    HANDLE hPipe = (HANDLE) _get_osfhandle(pipe_fd);
    DWORD bytes_avail;

    if (hPipe == INVALID_HANDLE_VALUE)
    {
        return FALSE;
    }

    if (! PeekNamedPipe(hPipe, NULL, 0, NULL, &bytes_avail, NULL))
    {
        return FALSE;
    }

    if (bytes_avail > 0)
    {
        return TRUE;
    }
    return FALSE;
#else /* select */
    fd_set rfds;
    struct timeval timeout;

    FD_ZERO(&rfds);
    FD_SET(pipe_fd, &rfds);
    timeout.tv_sec = 0;
    timeout.tv_usec = 0;

    if (select(pipe_fd + 1, &rfds, NULL, NULL, &timeout) > 0)
    {
        return TRUE;
    }

    return FALSE;
#endif
}

gboolean
ws_read_string_from_pipe(ws_pipe_handle read_pipe, gchar *buffer,
                         size_t buffer_size)
{
    size_t total_bytes_read;
    size_t buffer_bytes_remaining;
#ifdef _WIN32
    DWORD bytes_to_read;
    DWORD bytes_read;
    DWORD bytes_avail;
#else
    size_t bytes_to_read;
    ssize_t bytes_read;
#endif

    if (buffer_size == 0)
    {
        /* XXX - provide an error string */
        return FALSE;
    }
    if (buffer_size == 1)
    {
        /* No room for an actual string */
        buffer[0] = '\0';
        return TRUE;
    }

    /*
     * Number of bytes of string data we can actually read, leaving room
     * for the terminating NUL.
     */
    buffer_size--;

    total_bytes_read = 0;
    for (;;)
    {
        buffer_bytes_remaining = buffer_size - total_bytes_read;
        if (buffer_bytes_remaining == 0)
        {
            /* The string won't fit in the buffer. */
            g_log(LOG_DOMAIN_CAPTURE, G_LOG_LEVEL_DEBUG, "Buffer too small (%zd).", buffer_size);
            buffer[buffer_size - 1] = '\0';
            return FALSE;
        }

#ifdef _WIN32
        /*
         * XXX - is there some reason why we do this before reading?
         *
         * If we're not trying to do UN*X-style non-blocking I/O,
         * where we don't block if there isn't data available to
         * read right now, I'm not sure why we do this.
         *
         * If we *are* trying to do UN*X-style non-blocking I/O,
         * 1) we're presumably in an event loop waiting for,
         * among other things, input to be available on the
         * pipe, in which case we should be doing "overlapped"
         * I/O and 2) we need to accumulate data until we have
         * a complete string, rather than just saying "OK, here's
         * the string".)
         */
        if (!PeekNamedPipe(read_pipe, NULL, 0, NULL, &bytes_avail, NULL))
        {
            break;
        }
        if (bytes_avail <= 0)
        {
            break;
        }

        /*
         * Truncate this to whatever fits in a DWORD.
         */
        if (buffer_bytes_remaining > 0x7fffffff)
        {
            bytes_to_read = 0x7fffffff;
        }
        else
        {
            bytes_to_read = (DWORD)buffer_bytes_remaining;
        }
        if (!ReadFile(read_pipe, &buffer[total_bytes_read], bytes_to_read,
            &bytes_read, NULL))
        {
            /* XXX - provide an error string */
            return FALSE;
        }
#else
        bytes_to_read = buffer_bytes_remaining;
        bytes_read = read(read_pipe, buffer, bytes_to_read);
        if (bytes_read == -1)
        {
            /* XXX - provide an error string */
            return FALSE;
        }
#endif
        if (bytes_read == 0)
        {
            break;
        }

        total_bytes_read += bytes_read;
    }

    buffer[total_bytes_read] = '\0';
    return TRUE;
}

/*
 * Editor modelines  -  http://www.wireshark.org/tools/modelines.html
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
