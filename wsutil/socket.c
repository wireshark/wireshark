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

#include "config.h"
#include "socket.h"

#include <stdlib.h>
#include <errno.h>

#include <wsutil/inet_addr.h>

#ifdef _WIN32
#include <wsutil/win32-utils.h>
#define in_port_t   uint16_t
#endif

char *
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
        errmsg = ws_strdup_printf("Couldn't initialize Windows Sockets: %s",
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

int
ws_socket_ptoa(struct sockaddr_storage *dst, const char *src,
                    uint16_t def_port)
{
    int ret = -1, af = -1;
    char *addr_src, *p;
    char *addr_str = NULL, *port_str = NULL;
    union {
        ws_in4_addr ip4;
        ws_in6_addr ip6;
    } addr;
    char *endptr;
    long num;
    in_port_t port;

    addr_src = g_strdup(src);

    /* Is it an IPv6/IPv4 literal address enclosed in braces? */
    if (*addr_src == '[') {
        addr_str = addr_src + 1;
        if ((p = strchr(addr_str, ']')) == NULL) {
            errno = EINVAL;
            goto out;
        }
        *p++ = '\0';
        if (*p == ':') {
            port_str = p + 1;
        }
        else if (*p != '\0') {
            errno = EINVAL;
            goto out;
        }
        if (ws_inet_pton6(addr_str, &addr.ip6)) {
            af = AF_INET6;
        }
        else if (ws_inet_pton4(addr_str, &addr.ip4)) {
            af = AF_INET;
        }
        else {
            errno = EINVAL;
            goto out;
        }
    }
    else {
        /* It is an IPv4 dotted decimal. */
        addr_str = addr_src;
        if ((p = strchr(addr_str, ':')) != NULL) {
            *p++ = '\0';
            port_str = p;
        }
        if (ws_inet_pton4(addr_str, &addr.ip4)) {
            af = AF_INET;
        }
        else {
            errno = EINVAL;
            goto out;
        }
    }

    if (port_str != NULL && *port_str != '\0') {
        num = strtol(port_str, &endptr, 10);
        /* We want the entire string to be a valid decimal representation. */
        if (endptr == port_str || *endptr != '\0' || num < 0 || num > UINT16_MAX) {
            errno = EINVAL;
            goto out;
        }
        port = g_htons(num);
    }
    else {
        port = g_htons(def_port);
    }

    /* sockaddr_storage is guaranteed to fit any sockaddr type. */
    if (af == AF_INET6) {
        struct sockaddr_in6 *sa = (struct sockaddr_in6 *)dst;
        memset(sa, 0, sizeof(struct sockaddr_in6));
        sa->sin6_family = AF_INET6;
        sa->sin6_port = port;
        memcpy(&sa->sin6_addr, &addr.ip6, sizeof(struct in6_addr));
        ret = 0;
    }
    else if (af == AF_INET) {
        struct sockaddr_in *sa = (struct sockaddr_in *)dst;
        memset(sa, 0, sizeof(struct sockaddr_in));
        sa->sin_family = AF_INET;
        sa->sin_port = port;
        memcpy(&sa->sin_addr, &addr.ip4, sizeof(struct in_addr));
        ret = 0;
    }
    else {
        ws_assert_not_reached();
    }

out:
    g_free(addr_src);
    return ret;
}
