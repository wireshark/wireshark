/* socket.c
 * Socket wrappers
 *
 * Copyright 2019, Gerald Combs
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include <config.h>

#include <glib.h>

#include <wsutil/socket.h>

#ifdef _WIN32
#include <wsutil/win32-utils.h>
#endif

gchar *
ws_init_sockets(void)
{
    char    *errmsg = NULL;
#ifdef _WIN32
    int      err;
    WORD     wVersionRequested;
    WSADATA  wsaData;

    wVersionRequested = MAKEWORD(2, 2);
    err = WSAStartup(wVersionRequested, &wsaData);
    if (err != 0) {
        errmsg = g_strdup_printf("Couldn't initialize Windows Sockets: %s",
                                 win32strerror(err));
    }
#endif
    return errmsg;
}

void
ws_cleanup_sockets(void)
{
#ifdef _WIN32
    /* XXX - any reason to check the error return? */
    WSACleanup();
#endif
}
